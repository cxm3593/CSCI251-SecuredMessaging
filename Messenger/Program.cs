/// CSCI 251 Project3 Secure_Messenger
/// Author: Chengyi Ma cxm3593
/// This is the main Messenger program
/// 
using System;
using PrimeGen;
using System.Numerics;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;


namespace Messenger
{
    /// <summary>
    /// The Messenger program that provide all the required functions
    /// </summary>
    class MessengerProgram
    {
        static async Task Main(string[] args)
        {
            // test
            // Encry_Decry_test();

            KeySystem keySystem = new KeySystem();
            KeyGenerator KG = new KeyGenerator();
            HttpClient client = new HttpClient();

            string server_address = "http://kayrun.cs.rit.edu:5000";

            if (args.Length != 0)
            {
                // Handle Argument Input 
                if (args[0] == "keyGen")
                {
					if(args.Length == 2)
					{
						int keySize;
						bool result = int.TryParse(args[1], out keySize);
						if (result == false || ((keySize % 8) != 0))
						{
							Console.WriteLine("Please Enter a valid keySize");
						}
						else
						{
							KG.generateKeys(keySize);
							byte[] privateKey_bytes = KG.getPrivateKey();
							string privateKey_base64 = Convert.ToBase64String(privateKey_bytes);
							keySystem.privateKey.key = privateKey_base64;


							byte[] publicKey_bytes = KG.getPublicKey();
							string publicKey_base64 = Convert.ToBase64String(publicKey_bytes);
							keySystem.publicKey.key = publicKey_base64;

							keySystem.privateKey.emails.Clear();
							keySystem.publicKey.email = null;

							keySystem.writeFiles();
						}
					}else
					{
						Console.WriteLine("Please enter keyGen <bitsize>");
					}

                    
                }
                else if(args[0] == "sendKey")
                {
                    string email;
                    if(args.Length == 2)
                    {
                        try
                        {
                            email = args[1];
                            string uri = server_address + "/Key/" + email;
                            
                            Dictionary<string, string> packageJson = new Dictionary<string, string>();
                            packageJson.Add("email", email);
                            packageJson.Add("key", keySystem.publicKey.key);
                            string body = JsonSerializer.Serialize(packageJson);

                            string response_Json = await PutMessage(client, uri, body);

                            //Write files
                            keySystem.publicKey.email = email;
                            if (keySystem.privateKey.emails.Contains(email) == false)
                            {
                                keySystem.privateKey.emails.Add(email);
                            }
                            keySystem.writeFiles();

                            Console.WriteLine("Key saved");
                        }
                        catch(Exception e)
                        {
                            Console.WriteLine("SendKey Error: {0}", e.Message);
                        }
                    }
					else{
						Console.WriteLine("Please enter sendKey <email>");
					}
                }
                else if(args[0] == "getKey")
                {
                    string email;
                    if(args.Length == 2)
                    {
                        try
                        {
                            email = args[1];
                            string uri = server_address + "/Key/" + email;
                            string response_Json = await GetMessage(client, uri);
                            Dictionary<string, string> other_key = JsonSerializer.Deserialize<Dictionary<string, string>>(response_Json);
                            // Write File
                            string keyFileName = email + ".key";
                            PublicKey pubKey = new PublicKey();
                            pubKey.email = other_key["email"];
                            pubKey.key = other_key["key"];

                            string otherKeyFileJson = JsonSerializer.Serialize(pubKey);
                            File.WriteAllText(keyFileName, otherKeyFileJson);
                        }
                        catch(Exception e)
                        {
                            Console.WriteLine("GetKey Exception: {0}", e.Message);
                        }
                        
                    }
                    else
                    {
                        Console.WriteLine("Please enter an email");
                    }
                }
                else if(args[0] == "sendMsg")
                {
                    string email;
                    string message;
                    if(args.Length == 3)
                    {
                        try
                        {
                            email = args[1];
                            message = args[2];

                            // Check email public key
                            string email_keyFile = email + ".key";
                            if (File.Exists(email_keyFile))
                            {
                                // Get key
                                string keyFile_Json = File.ReadAllText(email_keyFile);
                                Dictionary<string, string> key_dict = JsonSerializer.Deserialize<Dictionary<string, string>>(keyFile_Json);
                                string pubkey = key_dict["key"];
                                KeyParser kp = new KeyParser(pubkey, true);
                                kp.parse();

                                // Encryption
                                byte[] msg_byte = Encoding.ASCII.GetBytes(message);
                                BigInteger M = new BigInteger(msg_byte);
                                BigInteger C = RSAEncryptor.RSA_Encrypt(M, kp.E, kp.N);

                                // Encode
                                byte[] C_bytes = C.ToByteArray();
                                string C_base64 = Convert.ToBase64String(C_bytes);

                                // Load message object
                                Dictionary<string, string> msg_dict = new Dictionary<string, string>();
                                msg_dict.Add("email", email);
                                msg_dict.Add("content", C_base64);
                                string body = JsonSerializer.Serialize(msg_dict);

                                // Send message object
                                string uri = server_address + "/Message/" + email;
                                string response_Json = await PutMessage(client, uri, body);
                                Console.WriteLine("Message Written");


                            }
                            else
                            {
                                Console.WriteLine("Cannot find the needed public key, please download it first before messaging");
                                Environment.Exit(0);
                            }

                        }
                        catch(Exception e)
                        {
                            Console.WriteLine("sendMsg Exception: {0}", e.Message);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Please enter: sendMsg <email> <message>");
                    }
                }
                else if(args[0] == "getMsg")
                {
                    string email;
                    if(args.Length == 2)
                    {
                        try
                        {
                            email = args[1];
                            // Validate email
                            if (keySystem.privateKey.emails.Contains(email))
                            {
                                // get json from server
                                string uri = server_address + "/Message/" + email;
                                string response_Json = await GetMessage(client, uri);
                                Dictionary<string, string> msg_dict = JsonSerializer.Deserialize<Dictionary<string, string>>(response_Json);
                                string msg_raw; // the base64 encrypted msg
                                msg_raw = msg_dict["content"];

                                // Decode raw message
                                byte[] msg_bytes = Convert.FromBase64String(msg_raw);
                                BigInteger C = new BigInteger(msg_bytes);

                                // Decryption
                                KeyParser kp = new KeyParser(keySystem.privateKey.key, false);
                                kp.parse();
                                BigInteger M = RSAEncryptor.RSA_Decrypt(C, kp.D, kp.N);
                                byte[] M_bytes = M.ToByteArray();
                                string message = Encoding.ASCII.GetString(M_bytes);

                                Console.WriteLine(message);

                            }
                            else
                            {
                                Console.WriteLine("Cannot find the needed private key.");
                            }
                        }
                        catch(Exception e)
                        {
                            Console.WriteLine("getMsg Exception: {0}", e.Message);
                        }
                        
                    }
                    else
                    {
                        Console.WriteLine("Please enter: getMsg <email>");
                    }
                }


            }
            

            //Console.WriteLine("Keysystem.public: " + keySystem.publicKey.key);
            //Console.WriteLine("Keysystem.private: " + keySystem.privateKey.key);

        }

        /// <summary>
        /// Private test method.
        /// </summary>
        private static void Encry_Decry_test()
        {
            // testing area for debug
            // string to BI
            string message = "Hello World";
            byte[] message_byte = Encoding.ASCII.GetBytes(message);
            BigInteger M = new BigInteger(message_byte);

            KeyGenerator keyGenerator = new KeyGenerator();
            keyGenerator.generateKeys();
            //Console.WriteLine("Keys: E: " + keyGenerator.E + " D: " + keyGenerator.D + " N: " + keyGenerator.N);

            Byte[] pub_key = keyGenerator.getPublicKey();
            string pub_key_base64str = Convert.ToBase64String(pub_key);
            //Console.WriteLine("Public Key: " + pub_key_base64str + " ; Size: " + pub_key.Length);
            KeyParser pub_KP = new KeyParser(pub_key_base64str, true);
            pub_KP.parse();
            Console.WriteLine("Parsed pub key: " + " E: " + (pub_KP.E == keyGenerator.E) + "; N: " + (pub_KP.N == keyGenerator.N) );

            BigInteger C = RSAEncryptor.RSA_Encrypt(M, pub_KP.E, pub_KP.N);

            Byte[] private_key = keyGenerator.getPrivateKey();
            string private_key_base64str = Convert.ToBase64String(private_key);
            //Console.WriteLine("Private Key: " + private_key_base64str + " ; Size: " + private_key.Length);
            KeyParser priv_KP = new KeyParser(private_key_base64str, false);
            priv_KP.parse();
            Console.WriteLine("Parsed private key: " + " D: " + (priv_KP.D == keyGenerator.D) + "; N: " + (priv_KP.N == keyGenerator.N));


            BigInteger M_decrypted = RSAEncryptor.RSA_Decrypt(C, priv_KP.D, priv_KP.N);
            byte[] M_decrypted_byte = M_decrypted.ToByteArray();
            string message_decrypted = Encoding.ASCII.GetString(M_decrypted_byte);
            Console.WriteLine("Decrypted: " + message_decrypted);

            // testing ends here
        }

        static async Task<string> GetMessage(HttpClient client , string uri)
        {
            string responseBody = "";
            try
            {
                HttpResponseMessage response = await client.GetAsync(uri);
                response.EnsureSuccessStatusCode();
                responseBody = await response.Content.ReadAsStringAsync();
                return responseBody;
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("GetMessage Error :{0} ", e.Message);
            }
            return responseBody;
        }

        static async Task<string> PutMessage(HttpClient client, string uri, string body)
        {
            string responseBody = "";
            HttpContent content = new StringContent(body, Encoding.UTF8, "application/json");
            try
            {
                HttpResponseMessage response = await client.PutAsync(uri, content);
                response.EnsureSuccessStatusCode();
                responseBody = await response.Content.ReadAsStringAsync();
                return responseBody;
            }
            catch(HttpRequestException e)
            {
                Console.WriteLine("PutMessage Error: {0}", e.Message);
            }
            return responseBody;
        }

    }

    /// <summary>
    /// An auxiliary class to do rsa encryption and decryption
    /// </summary>
    class RSAEncryptor
    {
        public static BigInteger RSA_Encrypt(BigInteger M, BigInteger E, BigInteger N)
        {
            BigInteger C = BigInteger.ModPow(M, E, N);
            return C;
        }

        public static BigInteger RSA_Decrypt(BigInteger C, BigInteger D, BigInteger N)
        {
            BigInteger M = BigInteger.ModPow(C, D, N);
            return M;
        }
    }

    /// <summary>
    /// KeyGenerate uses RSA algorithm to generate a public key and a private key for secure messaging
    /// </summary>
    class KeyGenerator {
        /// <summary>
        /// This is an auxiliary function that helps to generate public & private keys if needed
        /// </summary>

        public BigInteger p { get; private set; }
        public BigInteger q { get; private set; }
        public BigInteger N { get; private set; }
        public BigInteger D { get; private set; }
        public BigInteger E { get; private set; }
        public BigInteger r { get; private set; }

        public void generateKeys()
        {
            // Generating p, q
            
            generatePQ();

            // Generate N
            N = p * q;

            // Generate Phi (r)
            r = (p - 1) * (q - 1);

            // Pick E
            E = 65537;

            // Calculate D
            D = modInverse(E, r);
        }

        public void generateKeys(int keysize)
        {
            // Generating p, q

            generatePQ(keysize);

            // Generate N
            N = p * q;

            // Generate Phi (r)
            r = (p - 1) * (q - 1);

            // Pick E
            E = 65537;

            // Calculate D
            D = modInverse(E, r);
        }



        /// <summary>
        /// This is an auxiliary function that helps to generate p & q for generating public & private keys.
        /// </summary>
        /// <param name="p"></param>
        /// <param name="q"></param>
        private void generatePQ()
        {
            PrimeSeeker.bits = 512;
            PrimeSeeker.count = 2;

            ParallelPrimeGen pp = new ParallelPrimeGen(2);
            List<BigInteger> pq_list = pp.generate_silent();

            this.p = pq_list[0];
            this.q = pq_list[1];
        }

        /// <summary>
        /// This is an auxiliary function that helps to generate p & q for generating public & private keys.
        /// </summary>
        /// <param name="p"></param>
        /// <param name="q"></param>
        private void generatePQ(int keysize)
        {
            PrimeSeeker.bits = keysize/2;
            PrimeSeeker.count = 2;

            ParallelPrimeGen pp = new ParallelPrimeGen(2);
            List<BigInteger> pq_list = pp.generate_silent();

            this.p = pq_list[0];
            this.q = pq_list[1];
        }

        /// <summary>
        /// This is an auxiliary function the helps to calculate modInverse;
        /// </summary>
        /// <param name="a"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1; while (a > 0)
            {
                BigInteger t = i / a, x = a; a = i % x; i = x; x = d; d = v - t * x; v = x;
            }
            v %= n; if (v < 0) v = (v + n) % n; return v;
        }

        /// <summary>
        /// generate a public key in the format of eeeeEEEE...EEnnnnNNNN...NNNN;
        /// </summary>
        /// <returns>Byte[]: the public key</returns>
        public Byte[] getPublicKey()
        {
            Byte[] E_byte = this.E.ToByteArray();
            Int32 E_size = E_byte.Length;
            Byte[] e_byte = BitConverter.GetBytes(E_size);
            Array.Reverse(e_byte);

            Byte[] N_byte = this.N.ToByteArray();
            Int32 N_size = N_byte.Length;
            Byte[] n_byte = BitConverter.GetBytes(N_size);
            Array.Reverse(n_byte);

            int size = 0;
            size += e_byte.Length;
            size += E_byte.Length;
            size += n_byte.Length;
            size += N_byte.Length;

            Byte[] pub_key = new Byte[size];
            int index = 0;
            e_byte.CopyTo(pub_key, index);
            index += e_byte.Length;
            E_byte.CopyTo(pub_key, e_byte.Length);
            index += E_byte.Length;
            n_byte.CopyTo(pub_key, index);
            index += n_byte.Length;
            N_byte.CopyTo(pub_key, index);

            // Console.WriteLine("Debug: " + e_byte.Length + " " + E_byte.Length + " " + n_byte.Length + " " + N_byte.Length);

            return pub_key;

        }
        /// <summary>
        /// Generate a private key in the format of ddddDDDD....DDDnnnnNNNN...NNN
        /// </summary>
        /// <returns>Byte[]: the private key</returns>
        public Byte[] getPrivateKey()
        {
            Byte[] D_byte = this.D.ToByteArray();
            Int32 D_size = D_byte.Length;
            Byte[] d_byte = BitConverter.GetBytes(D_size);
            Array.Reverse(d_byte);

            Byte[] N_byte = this.N.ToByteArray();
            Int32 N_size = N_byte.Length;
            Byte[] n_byte = BitConverter.GetBytes(N_size);
            Array.Reverse(n_byte);

            int size = 0;
            size += d_byte.Length;
            size += D_byte.Length;
            size += n_byte.Length;
            size += N_byte.Length;

            Byte[] priv_key = new Byte[size];
            int index = 0;
            d_byte.CopyTo(priv_key, index);
            index += d_byte.Length;
            D_byte.CopyTo(priv_key, index);
            index += D_byte.Length;
            n_byte.CopyTo(priv_key, index);
            index += n_byte.Length;
            N_byte.CopyTo(priv_key, index);

            // Console.WriteLine("Debug: " + d_byte.Length + " " + D_byte.Length + " " + n_byte.Length + " " + N_byte.Length);

            return priv_key;
        }

        
    }

    /// <summary>
    /// KeyParser parse a public key or private key into N, D, E in a meaningful format
    /// </summary>
    class KeyParser
    {

        private string raw_string;
        public byte[] key_bytes;

        public BigInteger E;
        public BigInteger D;
        public BigInteger N;

        public bool isPublic;


        public KeyParser(string base64String, bool isPublic) 
        {
            raw_string = base64String;
            this.isPublic = isPublic;
        }

        /// <summary>
        /// Start Parsing the key base64 string
        /// </summary>
        public void parse()
        {
            key_bytes = Convert.FromBase64String(raw_string);

            int index = 0;
            byte[] first_indicator_byte = new byte[4];
            
            for(int i=0; i<4; i++)
            {
                first_indicator_byte[i] = key_bytes[i];
            }
            index += 4;
            Array.Reverse(first_indicator_byte);
            int first_indicator = BitConverter.ToInt32(first_indicator_byte); // e or d

            // Getting E or D
            byte[] EorD_byte = new byte[first_indicator];
            for(int i=0; i<first_indicator; i++)
            {
                EorD_byte[i] = key_bytes[i + index];
                
            }
            index += first_indicator;
            if (isPublic == true)
            {
                this.E = new BigInteger(EorD_byte);
            }
            else
            {
                this.D = new BigInteger(EorD_byte);
            }

            // Getting second_indicator
            byte[] second_indicator_byte = new byte[4];
            
            for(int i=0; i<4; i++)
            {
                second_indicator_byte[i] = key_bytes[i + index];
            }
            index += 4;
            Array.Reverse(second_indicator_byte);
            int second_indicator = BitConverter.ToInt32(second_indicator_byte);

            // Getting N
            byte[] N_byte = new byte[second_indicator];
            for (int i = 0; i < second_indicator; i++)
            {
                N_byte[i] = key_bytes[i + index];
            }
            index += second_indicator;
            this.N = new BigInteger(N_byte);
        }

        

    }

    class KeySystem
    {
        public PrivateKey privateKey { get; set; }

        public PublicKey publicKey { get; set; }


        string publicKeyFile = "public.key";
        string privateKeyFile = "private.key";


        public KeySystem()
        {
            privateKey = new PrivateKey();
            publicKey = new PublicKey();
            try
            {
                checkKeyFiles();
            }
            catch
            {
                // No need to do anything
            }
        }

        private void checkKeyFiles()
        {
            

            // check public key file
            if (!File.Exists(publicKeyFile))
            {
                File.Create(publicKeyFile);
            }
            else
            {
                string jsonstring = File.ReadAllText(publicKeyFile);
                publicKey = JsonSerializer.Deserialize<PublicKey>(jsonstring);
            }

            // check private key file
            if (!File.Exists(privateKeyFile))
            {
                File.Create(privateKeyFile);
            }
            else
            {
                string jsonstring = File.ReadAllText(privateKeyFile);
                privateKey = JsonSerializer.Deserialize<PrivateKey>(jsonstring);
            }
        }

        public void setPrivateKey(string key)
        {
            this.privateKey.key = key;
        }

        public void writeFiles()
        {
            // Write private key file
            try
            {
                string jsonstring = JsonSerializer.Serialize(privateKey);
                File.WriteAllText(privateKeyFile, jsonstring);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            try
            {
                string jsonstring = JsonSerializer.Serialize(publicKey);
                File.WriteAllText(publicKeyFile, jsonstring);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }

    class PrivateKey
    {
        public List<string> emails { get; set; }
        public string key { get; set; }

        public PrivateKey()
        {
            emails = new List<string>();
        }
        
    }

    class PublicKey
    {
        public string email { get; set; }
        public string key { get; set; }
    }
}
