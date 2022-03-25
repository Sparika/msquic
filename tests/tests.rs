use std::{sync::{Arc, Mutex, mpsc}, ptr, net::Ipv4Addr, convert::TryInto};

use libc::c_void;
use msquic::{Api, Connection, Configuration, Stream, Buffer, Registration, Handle, StreamEvent, ConnectionEvent, CertificateFile, CertificateUnion, Addr, ListenerEvent, CredentialConfig, SEND_FLAG_FIN};

const DEFAULT_IO_SIZE: usize = 0x10000;
const CLIENT_APP_NAME: &[u8] = "demo_client\0".as_bytes();
const SERVER_APP_NAME: &[u8] = "demo_server\0".as_bytes();
static ALPN: &str = "demo";

enum Message {
    NewClient(Box<Mutex<Client>>),
    ClientCompleted(u64)
}
static mut SENDER: Option<Mutex<Box<mpsc::Sender<Message>>>> = None;
static mut MsQuicAPI: Option<Api> = None;

pub struct Client {
    pub data: Box<[u8; DEFAULT_IO_SIZE]>,
    pub buffer: Box<Buffer>,
    // Respect order of msquic elements so they are dropped in correct order to avoid deadlock of MsQuic
    // Members of struct are dropped in order of declaration.
    pub stream: Option<Box<Stream>>,
    pub connection: Option<Box<Connection>>, // Need Stream closed
    pub configuration: Option<Box<Configuration>>,
    pub registration: Option<Box<Registration>>, // Need Connection and Configuration closed
    // For the demo we use a static API common to clients and server so this part is commented
    //pub msquic_api: Box<Api>,                    // Need to be last
}

/*pub struct MsQuic {
    pub configuration: Box<msquic::Configuration>,
    // For the demo we use a static API common to clients and server so this part is commented
    //pub api: Api,
}*/
pub struct Server {
    clients: Vec<Box<Mutex<Client>>>,
    configuration: Box<msquic::Configuration>,
    registration: msquic::Registration,
    //api: Arc<MsQuic>,
}


impl Client {
    pub fn new() -> Client {
        let mut data = Box::new([0 as u8; DEFAULT_IO_SIZE]);
        let buffer = Box::new(Buffer {
            length: DEFAULT_IO_SIZE as u32,
            buffer: data.as_mut_ptr(),
        });
        Client {
            registration: None,
            configuration: None,
            connection: None,
            stream: None,
            data,
            buffer,
        }
    }

    fn connect(&mut self, ip: Ipv4Addr, port: u16) {
        // Setup the registration.
        let config = msquic::RegistrationConfig {
            app_name: std::ffi::CStr::from_bytes_with_nul(CLIENT_APP_NAME)
                .unwrap()
                .as_ptr(),
            execution_profile: msquic::EXECUTION_PROFILE_LOW_LATENCY,
        };
        let registration = Box::new(msquic::Registration::new(unsafe{MsQuicAPI.as_ref().unwrap()}, &config));
        self.registration = Some(registration);

        // Setup the configuration.
        let configuration = Box::new(msquic::Configuration::new(
            self.registration.as_ref().unwrap(),
            &ALPN.into(),
            msquic::Settings::new()
                .set_peer_bidi_stream_count(100)
                .set_peer_unidi_stream_count(3),
        ));
        let mut credential_config = CredentialConfig::new_client();
        credential_config.cred_flags |= msquic::CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        configuration.load_credential(&credential_config);
        self.configuration = Some(configuration);

        // Setup the connection
        let connection = Box::new(msquic::Connection::new(self.registration.as_ref().unwrap()));
        connection.open(
            self.registration.as_ref().unwrap(),
            connection_client_callback,
            self as *const Client as *const c_void,
        );
        connection.start(self.configuration.as_ref().unwrap(), &ip.to_string(), port);
        self.connection = Some(connection);
    }

    /// Start the test stream
    fn start_stream(&mut self) {
        let stream = Box::new(Stream::new(
            (unsafe{MsQuicAPI.as_ref().unwrap()} as *const Api) as *const c_void,
        ));
        println!("stream");
        stream.open(
            self.connection.as_ref().unwrap(),
            msquic::STREAM_OPEN_FLAG_NONE,
            stream_client_callback,
            self as *const Client as *const c_void,
        );
        println!("open");
        stream.start(msquic::STREAM_START_FLAG_NONE);
        println!("start");
        self.stream = Some(stream);
    }

    pub fn send(&mut self, flag: msquic::SendFlags) {
        let stream = unsafe { &*(self.stream.as_ref().unwrap().as_ref() as *const Stream) };
        stream.send(
            &self.buffer,
            1,
            flag,
            self as *const Client as *const c_void,
        );
    }
}

extern "C" fn stream_client_callback(stream: Handle, context: *mut c_void, event: &StreamEvent) -> u32 {
    match event.event_type {
        msquic::STREAM_EVENT_RECEIVE => {
            println!("[client] Receive");
            let client = unsafe { &*(context as *const Client) };
            let buffer = unsafe { *event.payload.receive.buffer };
            let data: Vec<u8> = buffer.into();
            let received_value =
                u64::from_be_bytes(data[..8].try_into().expect("slice size incorrect"));

                
            let tx = unsafe { SENDER.as_ref().unwrap().lock().unwrap().clone() };
            match tx.send(Message::ClientCompleted(received_value)) {
                Ok(_) => (),
                Err(_) => panic!(),
            }
        }
        msquic::STREAM_EVENT_SHUTDOWN_COMPLETE => {
            println!("[client] stream shutdown complete");
            let client = unsafe { &mut *(context as *mut Client) };
            client.stream.take().unwrap().close();
        }
        _ => println!("[client] stream event {}", event.event_type)
    }
    0
}

pub(crate) extern "C" fn connection_client_callback(
    connection: Handle,
    context: *mut c_void,
    event: &ConnectionEvent,
) -> u32 {
    let client = unsafe { &mut *(context as *mut Client) };
    match event.event_type {
        _ => println!("[client] connection event {}", event.event_type)
    }
    0
}

impl<'a> Server {
    pub fn new(certificate: String, private_key: String) -> Server {
        //let api = Api::new();
        // Setup the registration.
        let config = msquic::RegistrationConfig {
            app_name: std::ffi::CStr::from_bytes_with_nul(SERVER_APP_NAME)
                .unwrap()
                .as_ptr(),
            execution_profile: msquic::EXECUTION_PROFILE_LOW_LATENCY,
        };
        let registration = msquic::Registration::new(unsafe{MsQuicAPI.as_ref().unwrap()}, &config);
        // Load the server configuration
        let configuration = Server::load_configuration(&registration, certificate, private_key);
        Server {
            registration,
            configuration,
            clients: Vec::new(),
        }
    }
    //
    // Helper function to load a server configuration. Uses the command line
    // arguments to load the credential part of the configuration.
    //
    fn load_configuration(
        registration: &Registration,
        certificate: String,
        private_key: String,
    ) -> Box<Configuration> {
        let mut settings = msquic::Settings::new();
        settings
            .set_idle_timeout_ms(10000)
            .set_peer_bidi_stream_count(100)
            .set_peer_unidi_stream_count(3);
        // Configures the server's resumption level to allow for resumption and
        // 0-RTT.
        // Not available in Rust yet
        // settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
        let mut certificate: Vec<u8> = certificate.into_bytes();
        certificate.push(0);
        let mut private_key: Vec<u8> = private_key.into_bytes();
        private_key.push(0);
        let certificate_file = std::ffi::CStr::from_bytes_with_nul(certificate.as_slice())
            .unwrap()
            .as_ptr();
        let private_key_file = std::ffi::CStr::from_bytes_with_nul(private_key.as_slice())
            .unwrap()
            .as_ptr();
        let certificate_file = CertificateFile {
            certificate_file,
            private_key_file,
        };

        let mut credential_config = msquic::CredentialConfig {
            cred_type: 0,
            cred_flags: 0,
            certificate: CertificateUnion {
                file: &certificate_file,
            },
            principle: ptr::null(),
            reserved: ptr::null(),
            async_handler: None,
            allowed_cipher_suites: 0,
        };
        credential_config.cred_flags = msquic::CREDENTIAL_FLAG_NONE;
        credential_config.cred_type = msquic::CREDENTIAL_TYPE_CERTIFICATE_FILE;

        //
        // Allocate/initialize the configuration object, with the configured ALPN
        // and settings.
        //
        let config = msquic::Configuration::new(&registration, &ALPN.into(), &settings);
        //
        // Loads the TLS credential part of the configuration.
        //
        config.load_credential(&credential_config);
        Box::new(config)
    }
}

pub(crate) extern "C" fn stream_server_callback(
    stream: Handle,
    context: *mut c_void,
    event: &StreamEvent,
) -> u32 {
    let client = unsafe { &*(context as *const Box<Mutex<Client>>) };
    match event.event_type {
        msquic::STREAM_EVENT_RECEIVE => {
            println!("[server] Receive");
            let mut client = client.lock().unwrap();
            let buffer = unsafe { *event.payload.receive.buffer };
            let data: Vec<u8> = buffer.into();
            //let tx = unsafe { SENDER.as_ref().unwrap().lock().unwrap().clone() };
            let mut received_value =
                u64::from_be_bytes(data[..8].try_into().expect("slice size incorrect"));
            println!("[server] Data={}", received_value);
            received_value += 2;

            client.buffer.length = std::mem::size_of::<u64>() as u32 + 1;
            client.data[0..std::mem::size_of::<u64>()]
                .copy_from_slice(&received_value.to_be_bytes());
            client.send(msquic::SEND_FLAG_FIN);
        }
        _ =>  println!("[server] stream event {}", event.event_type),
    }
    0
}

//
// The server's callback for connection events from MsQuic.
//
pub(crate) extern "C" fn connection_server_callback(
    _connection: Handle,
    context: *mut c_void,
    event: &ConnectionEvent,
) -> u32 {
    let client = unsafe { &*(context as *const Box<Mutex<Client>>) };
    match event.event_type {
        msquic::CONNECTION_EVENT_PEER_STREAM_STARTED => {
            println!("[server] Peer stream started");
            let mut client = client.lock().unwrap();
            let stream = Box::new(Stream::from_parts(
                unsafe { event.payload.peer_stream_started.stream },
                unsafe{MsQuicAPI.as_ref().unwrap()},
            ));
            client.stream = Some(stream);
            client
                .stream
                .as_ref()
                .unwrap()
                .set_callback_handler(stream_server_callback, context);
        }
        _ => println!("[server] connection event {}", event.event_type)
    }
    0
}

/// The server's callback for listener events from MsQuic.
pub(crate) extern "C" fn listener_server_callback(
    _listener: Handle,
    context: *mut c_void,
    event: &ListenerEvent,
) -> u32 {
    let msquic_configuration = unsafe { &*(context as *const Box<Configuration>) };
    /*
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    */
    match event.event_type {
        msquic::LISTENER_EVENT_NEW_CONNECTION => {
            println!("[server] New connection");
            // A new connection is being attempted by a client. For the handshake to
            // proceed, the server must provide a configuration for QUIC to use. The
            // app MUST set the callback handler before returning.
            //
            let mut data = Box::new([0 as u8; DEFAULT_IO_SIZE]);
            let buffer = Box::new(Buffer {
                length: DEFAULT_IO_SIZE as u32,
                buffer: data.as_mut_ptr(),
            });
            let connection = Some(Box::new(Connection::from_parts(
                unsafe { event.payload.new_connection.connection },
                unsafe{MsQuicAPI.as_ref().unwrap()},
            )));
            let client = Client {
                registration: None,
                configuration: None,
                connection,
                stream: None,
                data,
                buffer,
            };
            let client = Box::new(Mutex::new(client));
            {
                let client_lock = client.lock().unwrap();
                client_lock
                    .connection
                    .as_ref()
                    .unwrap()
                    .set_callback_handler(
                        connection_server_callback,
                        (&client as *const Box<Mutex<Client>>) as *const c_void,
                    );
                client_lock
                    .connection
                    .as_ref()
                    .unwrap()
                    .set_configuration(msquic_configuration.as_ref());
            }
            let tx = unsafe { SENDER.as_ref().unwrap().lock().unwrap().clone() };
            match tx.send(Message::NewClient(client)) {
                Ok(_) => (),
                Err(_) => panic!(),
            }
        }
        _ => println!("[server] listener event {}", event.event_type),
    }
    0
}



fn run_client(ip: Ipv4Addr, port: u16, value: u64) -> Result<Box<Client>, ()> {
    // Create client and connect to the server
    let mut client = Box::new(Client::new());
    println!("client");
    client.connect(ip, port);

    println!("connect");
    // Init test stream
    client.start_stream();
    println!("start");

    // Send value on stream with FIN flag
    client.buffer.length = std::mem::size_of::<u64>() as u32 + 1;
    client.data[0..std::mem::size_of::<u64>()].copy_from_slice(&value.to_be_bytes());
    client.send(msquic::SEND_FLAG_NONE);
    println!("send");

    // Return client
    Ok(client)
}


fn run_server(port: u16, certificate: String, private_key: String) -> Result<Box<Server>, ()> {
    // Configures the address used for the listener to listen on all IP
    // addresses and the given UDP port.
    let address = Addr::ipv4(msquic::ADDRESS_FAMILY_UNSPEC, port.to_be(), 0);
    let mut server = Box::new(Server::new(certificate, private_key));
    // Create/allocate a new listener object.
    let listener = msquic::Listener::new(
        &server.registration,
        listener_server_callback,
        (&server.configuration as *const Box<Configuration>) as *const c_void,
    );
    // Starts listening for incoming connections.
    listener.start(&ALPN.into(), 1, &address);
    // Continue listening for connections ctrl_c.
    Ok(server)
}

fn run_demo(value: u64) -> u64{
    println!("Begin demo");
    // Create a MPSC channel to get notifications from callbacks
    // As it is demo, we use the same channel to get both Server and Client events
    let (tx, rx) = mpsc::channel::<Message>();
    unsafe {
        SENDER = Some(Mutex::new(Box::new(tx)));
        MsQuicAPI = Some(msquic::Api::new());
    }
    let mut server = run_server(4433, String::from("./tests/server.cert"), String::from("./tests/server.key")).unwrap();
    println!("server ok");
    let mut client = run_client(Ipv4Addr::LOCALHOST, 4433, value).unwrap();
    println!("client ok");
    
    let mut result = 0;

    loop {
        // The loop handles storing connections and streams while they are needed
        match rx.try_recv() {
            Ok(Message::NewClient(client)) => {
                // Store client to avoid it being dropped
                server.clients.push(client);
            }
            Ok(Message::ClientCompleted(value)) => {
                result = value;
                break;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                // panic is for integration test purpose
                panic!("MPSC Disconnected");
                break;
            }
            Err(mpsc::TryRecvError::Empty) => (),
        }
    }

    // Close stream and connection
    //server.clients.drain(..).for_each(drop);

    /*client.stream.take().unwrap();
    client.connection.take().unwrap().close();

*/
drop(client);
server.clients.drain(..).for_each(drop);
//drop(server);
unsafe{MsQuicAPI.take()};
    println!("result: {}", result);
    result
}

#[test]
fn it_adds_two() {
    assert_eq!(run_demo(40), 42);
}