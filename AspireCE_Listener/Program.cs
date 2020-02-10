using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using MySql;
using MySql.Data;
using MySql.Data.MySqlClient;
using Json.Net;
using System.Security.Cryptography;

namespace AspireCE_Listener
{
    class Program
    {
        public static int PORT = 6498;
        public static string CONNECTION_STRING = "server=ip;user=user;password=password;port=3306;database=database;Sslmode=none";

        static long unixTime()
        {
            return ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();
        }
		
		// RC4 Encryption
        public static byte[] Encrypt(byte[] pwd, byte[] data)
        {
            int a, i, j, k, tmp;
            int[] key, box;
            byte[] cipher;

            key = new int[256];
            box = new int[256];
            cipher = new byte[data.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = pwd[i % pwd.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < data.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

		// RC4 Decrypt
        public static byte[] Decrypt(byte[] pwd, byte[] data)
        {
            return Encrypt(pwd, data);
        }

        static void Main(string[] args)
        {
            Console.WriteLine($"Aspire CE Listening on port {PORT}.");

            TcpListener server = new TcpListener(IPAddress.Any, PORT);
            server.Start();

            while (true)
            {
                byte[] buffer = new byte[0x300];

                TcpClient client = server.AcceptTcpClient();
                NetworkStream stream = client.GetStream();

                int packetSize = stream.Read(buffer, 0, buffer.Length);
                Thread connection = new Thread(() => handleConnection(buffer, client, stream));
                connection.Start();
            }
        }

        static void handleConnection(byte[] buffer, TcpClient client, NetworkStream stream)
        {
            int packetId = buffer[0];
            switch (packetId) // choose what todo based on the packet id sent from the client
            {
                // Redeem Token
                case 0:
                    handleToken(buffer, client, stream);
                    break;
                // Normal Connection
                case 1:
                    handleNormal(buffer, client, stream);
                    break;
                // Handle Cheat
                case 2:
                    handleCheat(buffer, client, stream);
                    break;
                case 3:
                    handleGeoIP(buffer, client, stream);
                    break;
                case 4:
                    handlePassword(buffer, client, stream);
                    break;
            }

            client.Close();
            stream.Close();
        }
		
		/*
		struct serverData
		{
			char packetId; // 0x00
			char fileHash[0x14]; // 0x01
			char CPUKey[0x10]; // 0x15
			char textHash[0x14]; // 0x25
			char securityHash[0x14]; // 0x39
			char Gamertag[0x20]; // 0x4D
			char message[0x100]; // 0x6D
			char cheatDecryptionKey[0x14]; // 0x16D
			char cheatURL[0x32]; // 0x181;
			char padding[0x14D];
		}; // Size = 0x1B3
		C++ struct mapped out for normal connection
		*/

        static void handleNormal(byte[] buffer, TcpClient client, NetworkStream stream)
        {
            string IP = client.Client.RemoteEndPoint.ToString().Split(':')[0];
            byte[] respBuffer = new byte[0x300];

			// Buffers for individual data in the buffer
            byte[] fileHash = new byte[0x14];
            byte[] CPUKey = new byte[0x10];
            byte[] textHash = new byte[0x14];
            byte[] securityHash = new byte[0x14];
            byte[] Gamertag = new byte[0x20];
            byte[] message = new byte[0x100];
            byte[] cheatDecryptionKey = new byte[0x14];
            byte[] cheatURL = new byte[0x32];

			// Copying the data from each additive in the buffer, to the correct new buffer
            Buffer.BlockCopy(buffer, 0x1, fileHash, 0, 0x14);
            Buffer.BlockCopy(buffer, 0x15, CPUKey, 0, 0x10);
            Buffer.BlockCopy(buffer, 0x25, textHash, 0, 0x14);
            Buffer.BlockCopy(buffer, 0x39, securityHash, 0, 0x14);
            Buffer.BlockCopy(buffer, 0x4D, Gamertag, 0, 0x20);
            Buffer.BlockCopy(buffer, 0x6D, message, 0, 0x100);

			// simple intregity check
            if (CPUKey[0] == 0)
                return;

			// message[0] gets filled on the conosle and sent here (the server)
            byte CURRENT_GAME = message[0];

            string security_hash = BitConverter.ToString(securityHash).Replace("-", "");

			// logging client connection (CPUKEY | IP)
            Console.WriteLine($"[Client Connected]: {BitConverter.ToString(CPUKey).Replace("-", "")} | {IP}");

            using (MySqlConnection connection = new MySqlConnection(CONNECTION_STRING))
            {
                connection.Open(); // open mysql connection

            retry:
                if (userExists(connection, CPUKey, securityHash))
                {
					// reading values from database
                    long expireTime = getLong(connection, CPUKey, "exp"), lastConnection = unixTime();
                    bool hashExempt = getBool(connection, CPUKey, "hash_exempt"), banned = getBool(connection, CPUKey, "banned"), lifetime = getBool(connection, CPUKey, "lifetime");
                    string dbSecurityHash = getString(connection, CPUKey, "security_hash");
					
                    string gamertag = Encoding.ASCII.GetString(Gamertag); // converting the ascii of the gamertag to an actual string

                    updateField(connection, CPUKey, "last_connection", lastConnection); // updating client last connection time in database
                    updateField(connection, CPUKey, "ip", IP); // updating client IP in database
					
                    if (gamertag != "" && gamertag != string.Empty) // making sure the gamertag isn't empty so we don't replace the previous gamertag with an empty tag
                        updateField(connection, CPUKey, "gamertag", gamertag);

                    if (security_hash != dbSecurityHash) // making sure unique hash recieved matches the first hash saved in the database
                    {
                        if (dbSecurityHash == "0") // updating hash for first new client, 0 is default value for new entry
                        {
                            updateField(connection, CPUKey, "security_hash", security_hash);
                        }
                        else
                        {
                            updateField(connection, CPUKey, "banned", true);
                            banned = true;
                            byte[] banMsg = Encoding.ASCII.GetBytes("You've been banned, contact support!");
                            Buffer.BlockCopy(banMsg, 0, message, 0, banMsg.Length);
                            Buffer.BlockCopy(message, 0, respBuffer, 0x6D, 0x100);
                            stream.Write(respBuffer, 0, respBuffer.Length);
							// user is banned, so we send them a message and tell them
                        }
                    }
					
					/*
					enum RESPONSE_PACKET_TYPE
					{
						BANNED_PACKET = 1,
						TOKEN_PACKET = 2,
						TIME_EXPIRED = 3,
						OUTDATED_PACKET = 4,
						AUTHED_PACKET = 5,
						PASSWORD_PACKET = 6,
					};
					C++ enum for packet id's for down below
					*/

                    if (!banned)
                    {
                        string loader_file = BitConverter.ToString(fileHash).Replace("-", ""); // convert hashes from bytes to a byte string
                        string loader_text = BitConverter.ToString(textHash).Replace("-", ""); // convert hashes from bytes to a byte string
                        Console.WriteLine($"Loader Hashes: {loader_file} | {loader_text}"); // printing the hashes the client sent to us
                        bool authed = false;

						// checking that their hashes match or they're allowed to bypass based on database
                        if (loader_file == readHash(connection, "loader_file") || hashExempt)
                        {
                            if (loader_text == readHash(connection, "loader_text") || hashExempt)
                            {
                                if (!readSettings(connection, "freemode")) // checking if database says freemode
                                {
                                    if (lifetime)
                                    {
                                        byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE Connected - You have lifetime!");
                                        Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                        authed = true;
                                        respBuffer[0] = 5;
										// setting message for a lifetime user
                                    }
                                    else if (!lifetime && expireTime > lastConnection)
                                    {
                                        long timeLeft = expireTime - lastConnection;
                                        long days = timeLeft / 60 / 60 / 24;
                                        long hours = (timeLeft / 60 / 60) % 24;
                                        long minutes = (timeLeft / 60) % 60;

                                        byte[] msg = new byte[0x100];
                                        if (days != 0)
                                            msg = Encoding.Default.GetBytes($"Aspire CE Connected - You have {days}d {hours}h {minutes}m remaining!");
                                        else if (days == 0)
                                            msg = Encoding.Default.GetBytes($"Aspire CE Connected - You have {hours}h {minutes}m remaining!");

                                        Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                        authed = true;

                                        respBuffer[0] = 5; // packet id
										// setting message for someone who has lifetime
                                    }
                                    else
                                    {
                                        byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE Connected - Your time is expired!");
                                        Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                        respBuffer[0] = 3;  // packet id
										// setting message for someone who has no time
                                    }
                                }
                                else
                                {
                                    byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE Connected - Freemode Enabled!");
                                    Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                    authed = true;
                                    respBuffer[0] = 5; // packet id
									// setting message for freemode
                                }
                            }
                            else
                            {
                                byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You've been banned for tampering!");
                                Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                updateField(connection, CPUKey, "banned", true);
                                respBuffer[0] = 1; // packet id
								// user is connecting with a modified version so we ban them and send a message
                            }
                        }
                        else
                        {
                            byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE Outdated - Downloading new update...");
                            respBuffer[0] = 4; // packet id
                            Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
							// file hash was incorrect, so we update them and tell them
                        }

                        if(authed && CURRENT_GAME != 0) // user has lifetime or normal time and is on a game we have cheats for
                        {
                            string gameUrl = "";
                            switch (CURRENT_GAME)
                            {
                                case 1:
                                    gameUrl = "/COD4_ACE_HAX.xex";
                                    break;
                                case 2:
                                    gameUrl = "/WAW_ACE_HAX.xex";
                                    break;
                                case 3:
                                    gameUrl = "/MW2_ACE_HAX.xex";
                                    break;
                                case 4:
                                    gameUrl = "/MW3_ACE_HAX.xex";
                                    break;
                                case 5:
                                    gameUrl = "/BO1_ACE_HAX.xex";
                                    break;
                                case 6:
                                    gameUrl = "/BO2_ACE_HAX.xex";
                                    break;
                                case 7:
                                    gameUrl = "/AW_ACE_HAX.xex";
                                    break;
                                case 8:
                                    gameUrl = "/GHOSTS_ACE_HAX.xex";
                                    break;
                                case 9:
                                    gameUrl = "/CSGO_ACE_HAX.xex";
                                    break;
									// setting the url to send back to the client to download the second executable
                            }
                            byte[] url = Encoding.ASCII.GetBytes(gameUrl); // converting the string into ascii and storing it
                            
                            Buffer.BlockCopy(url, 0, cheatURL, 0, url.Length); // copying the stored string into the buffer created at the start of the function
                            cheatURL = Encrypt(securityHash, cheatURL); // encrypting the url with their unique hash
                            Buffer.BlockCopy(cheatURL, 0, respBuffer, 0x181, 0x32); // copying the encrypted buffer into the response buffer
                            Gamertag[0] = 0x45; // value we set and send back so the client knows to start downloading the second executable
                            Buffer.BlockCopy(Gamertag, 0, respBuffer, 0x4D, 0x20); // then copy that into the response buffer as well
                        }

                        if (authed && (getString(connection, CPUKey, "pw_sha1") == "0")) // check if client hasn't registered a password yet
                        {
                            Gamertag[0] = 9; // value we set to let the client know to start the password setup
                            Buffer.BlockCopy(Gamertag, 0, respBuffer, 0x4D, 0x20); // copy that into the response buffer
                        }

                        Buffer.BlockCopy(message, 0, respBuffer, 0x6D, 0x100); // copy the message we were setting above into the reponse buffer
                        Buffer.BlockCopy(cheatDecryptionKey, 0, respBuffer, 0x16D, 0x14); // copy the cheat decryption key into the response buffer

                        stream.Write(respBuffer, 0, respBuffer.Length); // finally, send the response buffer to the client
                    }
                    else // client is banned
                    {
                        byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You're Banned!");
                        Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                        updateField(connection, CPUKey, "banned", true);
                        respBuffer[0] = 1; // packet id

                        Buffer.BlockCopy(message, 0, respBuffer, 0x6D, 0x100); // copy our message into the response buffer

                        stream.Write(respBuffer, 0, respBuffer.Length); // send the response buffer to the client
                    }
                }
                else // if user didn't get created the first time, try again
                    goto retry;


                connection.Close(); // close the mysql connection
            }
        }
		
		/*
		struct tokenData
		{
			char packetId; // 0x00
			char fileHash[0x14]; // 0x01
			char CPUKey[0x10]; // 0x15
			char textHash[0x14]; // 0x25
			char securityHash[0x14]; // 0x39
			char token[0x8]; // 0x4D
			char message[0x100]; // 0x55
			char padding[0x1AB];
		}; // Size = 0x155
		C++ struct mapped out for down below
		*/

        static void handleToken(byte[] buffer, TcpClient client, NetworkStream stream)
        {
            string IP = client.Client.RemoteEndPoint.ToString().Split(':')[0];
            byte[] respBuffer = new byte[buffer.Length];

			// create buffers to store the individual data
            byte[] fileHash = new byte[0x14];
            byte[] CPUKey = new byte[0x10];
            byte[] textHash = new byte[0x14];
            byte[] securityHash = new byte[0x14];
            byte[] message = new byte[0x100];
            byte[] token = new byte[8];

			// copy the data from their position in the entire recieve buffer to their spot
            Buffer.BlockCopy(buffer, 0x1, fileHash, 0, 0x14);
            Buffer.BlockCopy(buffer, 0x15, CPUKey, 0, 0x10);
            Buffer.BlockCopy(buffer, 0x25, textHash, 0, 0x14);
            Buffer.BlockCopy(buffer, 0x39, securityHash, 0, 0x14);
            Buffer.BlockCopy(buffer, 0x4D, token, 0, 8);

            if (CPUKey[0] == 0) // simple integrity check
                return;

            string security_hash = BitConverter.ToString(securityHash).Replace("-", ""); // convert the bytes into a byte string

			// print client connection CPUKEY | IP
            Console.WriteLine($"[Token Connected]: {BitConverter.ToString(CPUKey).Replace("-", "")} | {IP}");

			// log the clients IP and cpukey and the token they're trying to redeem
            File.AppendAllText("Logs.txt", $"[TOKEN LOG] IP: {IP} | CPUKey: {BitConverter.ToString(CPUKey).Replace("-", "")} | Token: {BitConverter.ToString(token).Replace("-", "")}\n");

            using (MySqlConnection connection = new MySqlConnection(CONNECTION_STRING))
            {
                connection.Open(); // open mysql connection

            retry:
                if (userExists(connection, CPUKey, securityHash))
                {
                    long expireTime = getLong(connection, CPUKey, "exp"), lastConnection = unixTime(); // read data from database
                    bool hashExempt = getBool(connection, CPUKey, "hash_exempt"), banned = getBool(connection, CPUKey, "banned"), lifetime = getBool(connection, CPUKey, "lifetime"); // read data from database
                    string dbSecurityHash = getString(connection, CPUKey, "security_hash"); // read data from database

                    updateField(connection, CPUKey, "last_connection", lastConnection); // update clients last connection in database
                    updateField(connection, CPUKey, "ip", IP); // update clients ip in database

                    if (security_hash != dbSecurityHash) // check if the recieved unique hash matches the first one stored in database
                    {
                        if (dbSecurityHash == "0") // if 0, the hash has never been set before, so set it
                        {
                            updateField(connection, CPUKey, "security_hash", security_hash);
                        }
                        else
                        {
                            updateField(connection, CPUKey, "banned", true);
                            banned = true;
                            byte[] banMsg = Encoding.ASCII.GetBytes("You've been banned, contact support!");
                            Buffer.BlockCopy(banMsg, 0, message, 0, banMsg.Length);
                            Buffer.BlockCopy(message, 0, respBuffer, 0x6D, 0x100);
                            stream.Write(respBuffer, 0, respBuffer.Length); // send the message that they're banned
							connection.Close(); // close the mysql connection
                            return; // do nore more code below
                        }
                    }

                    if (!banned)
                    {
						// convert the bytes to byte strings
                        string loader_file = BitConverter.ToString(fileHash).Replace("-", "");
                        string loader_text = BitConverter.ToString(textHash).Replace("-", "");

						// compare hashes with hashes in database or check if they can bypass it
                        if (loader_file == readHash(connection, "loader_file") || hashExempt)
                        {
                            if (loader_text == readHash(connection, "loader_text") || hashExempt)
                            {
                                if (!readSettings(connection, "freemode")) // check if we're not in freemode
                                {
                                    string sToken = Encoding.ASCII.GetString(token); // convert ascii of token to string
                                    if (sToken.All(char.IsLetterOrDigit) && tokenExists(connection, sToken)) // check that the token is only letters and numbers, and the token exists in the database
                                    {
                                        if ((getTokenString(connection, sToken) == "0")) // check no one has used the token
                                        {
                                            redeemToken(connection, sToken, BitConverter.ToString(CPUKey).Replace("-", "")); // mark the token as redeemed by setting their cpukey along with it
                                            long tokenLength = getTokenLength(connection, sToken); // get token length in seconds
                                            long days = tokenLength / 60 / 60 / 24; // convert those seconds into days
                                            long currentExp = getLong(connection, CPUKey, "exp"); // get their current remaining time
                                            if (tokenLength != 9999) // check tokens not a lifetime token
                                            {
                                                if (currentExp > lastConnection) // if their current expire time is greater than their last connection
                                                {
                                                    currentExp += tokenLength; // add their new time onto previous time
                                                    updateField(connection, CPUKey, "exp", currentExp); // set their new time in database
                                                }
                                                else // they don't have any current time
                                                {
                                                    updateField(connection, CPUKey, "exp", tokenLength + lastConnection); // set their expire time to current time + token length
                                                }

                                                byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You've redeemed {days} day(s)!");
                                                Buffer.BlockCopy(msg, 0, message, 0, msg.Length); // copy the message into the message buffer we created above
                                            }
                                            else // the token is a lifetime token
                                            {
                                                updateField(connection, CPUKey, "exp", 0); // set their expire time to 0
                                                updateField(connection, CPUKey, "lifetime", true); // set lifetime to 1

                                                byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You've redeemed lifetime!");
                                                Buffer.BlockCopy(msg, 0, message, 0, msg.Length); // copy the message buffer we created above
                                            }
                                        }
                                        else // the token is used already
                                        {
                                            byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - Token already redeemed!");
                                            Buffer.BlockCopy(msg, 0, message, 0, msg.Length); // copy the message into the message buffer we created above
                                        }
                                    }
                                    else // entered an invalid token
                                    {
                                        byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - Token is invalid!");
                                        Buffer.BlockCopy(msg, 0, message, 0, msg.Length); // copy the message into the message buffer we created above
                                    }
                                }
                                else // database says freemode
                                {
                                    byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You can't redeem tokens in freemode!");
                                    Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                }

                            }
                            else // user modified the executable memory
                            {
                                byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You've been banned for tampering!");
                                Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                updateField(connection, CPUKey, "banned", true); // ban the client
                                respBuffer[0] = 1; // set packet id to banned
                            }
                        }
                        else // connected with an old file/modified file
                        {
                            byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE Outdated - Downloading new update...");
                            respBuffer[0] = 4; // packet id
                            Buffer.BlockCopy(msg, 0, message, 0, msg.Length); // copy the message into the message buffer we created above
                        }

                        Buffer.BlockCopy(message, 0, respBuffer, 0x55, 0x100); // copy the message into the response buffer

                        stream.Write(respBuffer, 0, respBuffer.Length); // send the response buffer
                    }
                    else
                    {
                        byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You're Banned!");
                        Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                        updateField(connection, CPUKey, "banned", true);
                        respBuffer[0] = 1; // packet id

                        Buffer.BlockCopy(message, 0, respBuffer, 0x55, 0x100); // copy the message into the response buffer

                        stream.Write(respBuffer, 0, respBuffer.Length); // send the buffer to the client
                    }
                }
                else // if client didn't get created, retry
                    goto retry;


                connection.Close(); // close the mysql connection
            }
        }
		
		/*
		struct cheatData
		{
			char packetId; // 0x00
			char fileHash[0x14]; // 0x01
			char CPUKey[0x10]; // 0x15
			char textHash[0x14]; // 0x25
			char securityHash[0x14]; // 0x39
			char message[0x100]; // 0x4D
			int addresses[0x40]; // 0x150
			char padding[0xB3];
		}; // Size = 0x250
		C++ struct mapped out for below
		*/

        static void handleCheat(byte[] buffer, TcpClient client, NetworkStream stream)
        {
            try
            {
                string IP = client.Client.RemoteEndPoint.ToString().Split(':')[0];
                byte[] respBuffer = new byte[buffer.Length];

				// create buffers to store the individual data
                byte[] fileHash = new byte[0x14];
                byte[] CPUKey = new byte[0x10];
                byte[] textHash = new byte[0x14];
                byte[] securityHash = new byte[0x14];
                byte[] Gamertag = new byte[0x20];
                byte[] message = new byte[0x100];
                byte[] cheatDecryptionKey = new byte[0x14];
                byte[] cheatURL = new byte[0x32];

                if (CPUKey[0] == 0) // simple integrity check
                    return;

				// Copying the data from each additive in the buffer, to the correct new buffer
                Buffer.BlockCopy(buffer, 0x1, fileHash, 0, 0x14);
                Buffer.BlockCopy(buffer, 0x15, CPUKey, 0, 0x10);
                Buffer.BlockCopy(buffer, 0x25, textHash, 0, 0x14);
                Buffer.BlockCopy(buffer, 0x39, securityHash, 0, 0x14);
                Buffer.BlockCopy(buffer, 0x4D, Gamertag, 0, 0x20);

                string security_hash = BitConverter.ToString(securityHash).Replace("-", ""); // convert the bytes to a byte string

                Console.WriteLine($"[Cheat Connected]: {BitConverter.ToString(CPUKey).Replace("-", "")} | {IP}"); // print CPUKEY | IP
                File.AppendAllText("Logs.txt", $"[CHEAT LOG] IP: {IP} | CPUKey: {BitConverter.ToString(CPUKey).Replace("-", "")}\n"); // log user connecting to the cheat executable IP | CPUKEY

                using (MySqlConnection connection = new MySqlConnection(CONNECTION_STRING))
                {
                    connection.Open(); // open mysql connection

                retry:
                    if (userExists(connection, CPUKey, securityHash))
                    {
                        long expireTime = getLong(connection, CPUKey, "exp"), lastConnection = unixTime(); // read data from database
                        bool hashExempt = getBool(connection, CPUKey, "hash_exempt"), banned = getBool(connection, CPUKey, "banned"), lifetime = getBool(connection, CPUKey, "lifetime"); // read data from database
                        string dbSecurityHash = getString(connection, CPUKey, "security_hash"); // read data from database
                        string gamertag = Encoding.ASCII.GetString(Gamertag); // convert gamertag ascii to string

                        updateField(connection, CPUKey, "last_connection", lastConnection); // update client last connection in database
                        updateField(connection, CPUKey, "ip", IP); // update client ip in database
						
                        if (gamertag != "" && gamertag != string.Empty) // make sure gamertag isn't empty so we don't update it to an empty gamertag
                            updateField(connection, CPUKey, "gamertag", gamertag);

                        if (security_hash != dbSecurityHash) // check if unique hash doesn't match the one stored in the database
                        {
                            if (dbSecurityHash == "0") // if its 0, it hasn't ever been updated
                            {
                                updateField(connection, CPUKey, "security_hash", security_hash);
                            }
                            else // it simply doesn't match, so ban them
                            {
                                updateField(connection, CPUKey, "banned", true);
                                banned = true;
                                byte[] banMsg = Encoding.ASCII.GetBytes("You've been banned, contact support!");
                                Buffer.BlockCopy(banMsg, 0, message, 0, banMsg.Length); // copy the messasge into the messsage buffer
                                Buffer.BlockCopy(message, 0, respBuffer, 0x6D, 0x100); // copy the message into the response buffer
                                stream.Write(respBuffer, 0, respBuffer.Length); // send it to client
								connection.Close(); // close mysql connection
                                return; // dont go any further
                            }
                        }

                        if (!banned)
                        {
							// convert bytes to byte strings
                            string loader_file = BitConverter.ToString(fileHash).Replace("-", "");
                            string loader_text = BitConverter.ToString(textHash).Replace("-", "");
							
                            Console.WriteLine($"Cheat Hashes: {loader_file} | {loader_text}");
							
                            bool authed = false;

							// check to see if executable hashes match
                            if (loader_file == readHash(connection, "bo2_file") || hashExempt)
                            {
                                if (loader_text == readHash(connection, "bo2_text") || hashExempt)
                                {
                                    if (!readSettings(connection, "freemode")) // if not in freemode
                                    {
                                        if (lifetime) // if client has lifetime
                                        {
                                            authed = true;
                                            respBuffer[0] = 5; // set authed packet id
                                        }
                                        else if (!lifetime && expireTime > lastConnection) // if not lifetime but has time
                                        {
                                            authed = true;
                                            respBuffer[0] = 5; // set authed packet id
                                        }
                                        else // client has no time
                                        {
                                            byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE Connected - Your time is expired!");
                                            Buffer.BlockCopy(msg, 0, message, 0, msg.Length); // copy message to buffer at the start
                                            respBuffer[0] = 3; // packet id
                                        }
                                    }
                                    else // database says freemode
                                    {
                                        authed = true;
                                        respBuffer[0] = 5; // authed packet id
                                    }
                                }
                                else
                                {
                                    byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You've been banned for tampering!");
                                    Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                                    updateField(connection, CPUKey, "banned", true);
                                    respBuffer[0] = 1;
									// client edited the executable memory
                                }
                            }
                            else // client is outdated
                            {
                                respBuffer[0] = 4;
                            }

                            if(authed) // if authed, then copy addresses into the response buffer
                            {
                                uint[] addrs = new uint[0x40];
                                setupAddresses(6, addrs);
                                Buffer.BlockCopy(addrs, 0, respBuffer, 0x150, 0x100);
                            }

                            stream.Write(respBuffer, 0, respBuffer.Length); // send the response buffer to client
                        }
                        else // client is banned
                        {
                            byte[] msg = Encoding.ASCII.GetBytes($"Aspire CE - You're Banned!");
                            Buffer.BlockCopy(msg, 0, message, 0, msg.Length);
                            updateField(connection, CPUKey, "banned", true); // set client to banned
                            respBuffer[0] = 1;
                            Buffer.BlockCopy(message, 0, respBuffer, 0x6D, 0x100); // copy message to response buffer
                            stream.Write(respBuffer, 0, respBuffer.Length); // send buffer to client
                        }
                    }
                    else // if couldn't create client in database, retry
                        goto retry;


                    connection.Close(); // close mysql connection
                }
            }
            catch (Exception g)
            {
                Console.WriteLine($"!!!!!!ERROR!!!!!!\n{g.Message}"); // print error message from exception
                return;
            }
        }

        static void setupAddresses(int game, uint[] addr)
        {
			// set addresses for BO2
            if (game == 6) // BO2
            {
                addr[0] = 0x841E1B30;
                addr[1] = 0x82C55D60;
                addr[2] = 0x82459CE4;
                addr[3] = 0x826A5FBC;
                addr[4] = 0x828B9F58;
                addr[5] = 0x8225EAA8;
                addr[6] = 0x8293D884;
                addr[7] = 0x826B0148;
                addr[8] = 0x8293E5C4;
                addr[9] = 0x828B8BA0;
                addr[10] = 0x828B86C0;
                addr[11] = 0x82275F78;
                addr[12] = 0x828B78F0;
                addr[13] = 0x828B6FD8;
                addr[14] = 0x821C7F58;
                addr[15] = 0x826BF988;
                addr[16] = 0x824015E0;
                addr[17] = 0x82414578;
                addr[18] = 0x821D03F0;
                addr[19] = 0x823599E0;
                addr[20] = 0x822544B0;
                addr[21] = 0x8225C568;
                addr[22] = 0x826BB4E0;
                addr[23] = 0x826C0598;
                addr[24] = 0x82496430;
                addr[25] = 0x82459C80;
                addr[26] = 0x827504D0;
                addr[27] = 0x82258840;
                addr[28] = 0x821C45B8;
                addr[29] = 0x821E64E0;
                addr[30] = 0x824CBFE0;
                addr[31] = 0x82C6FDD0;
                addr[32] = 0x82C153E8;
                addr[33] = 0x82C153EC;
                addr[34] = 0x82CBC168;
                addr[35] = 0x83BA2A18;
                addr[36] = 0x40;
                addr[37] = 0xB4;
                addr[38] = 0x38;
                addr[39] = 0x148;
                addr[40] = 0x82BC2774;
                addr[41] = 0x18;
                addr[42] = 0x82259BC8;
                addr[43] = 0x826C6E6C;
                addr[44] = 0x82C15758;
                addr[45] = 0x822DFB90;
                addr[46] = 0x82258520;
                addr[47] = 0x82257E30;
                addr[48] = 0x82258CE4;
                addr[49] = 0x82258FAC;
                addr[50] = 0x8225900C;
                addr[51] = 0x82258D60;
                addr[52] = 0x82259B40;
                addr[53] = 0x82717AE0;
                addr[54] = 0x822DDE20;
                addr[55] = 0x827D33F0;
                addr[56] = 0x82BBC554;
                addr[57] = 0x82BBAE68;
                addr[58] = 0x82C70F4C;
                addr[59] = 0xC403C368;
            }
        }

        static bool userExists(MySqlConnection connection, byte[] CPUKey, byte[] securityHash)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            string security_hash = BitConverter.ToString(securityHash).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"SELECT COUNT(*) FROM consoles WHERE cpukey='{cpukey}' LIMIT 1;", connection);
            int count = Convert.ToInt32(cmd.ExecuteScalar());
            if (count > 0) // if user count is greater than 0 then they exist
            {
                return true;
            }
            else
            {
                cmd = new MySqlCommand($"INSERT INTO consoles (cpukey, security_hash) VALUES ('{cpukey}',  '{security_hash}')", connection);
                cmd.ExecuteNonQuery();
                return false;
            }
        }

		// Geo IP function which recives IPs of players in the clients game on xbox, and we get the geo location and information about the ip and send it back to the client do display
        static void handleGeoIP(byte[] buffer, TcpClient client, NetworkStream stream)
        {
            try
            {
                string connectionIP = client.Client.RemoteEndPoint.ToString().Split(':')[0];
                byte[] respBuffer = new byte[0x113];

                byte[] recvIP = new byte[4];
                byte[] recvGamertag = new byte[32];
                byte[] recvXuid = new byte[8];

                Buffer.BlockCopy(buffer, 1, recvIP, 0, 4);
                Buffer.BlockCopy(buffer, 5, recvGamertag, 0, 32);
                Buffer.BlockCopy(buffer, 37, recvXuid, 0, 8);

                if (recvIP[0] == 0 && recvIP[1] == 0 && recvIP[2] == 0 && recvIP[3] == 0) // integrity to make sure ip isn't invalid
                    return;

                byte[] rCountry = new byte[64];
                byte[] rState = new byte[64];
                byte[] rCity = new byte[64];
                byte[] rZipCode = new byte[64];
                byte[] rISP = new byte[64];
                bool mobile = false, proxy = false;

                string IP = $"{recvIP[0]}.{recvIP[1]}.{recvIP[2]}.{recvIP[3]}", // convert the byte IP to a string
                    Gamertag = Encoding.ASCII.GetString(recvGamertag), // convert the ascii gamertag into a string
					xuid = BitConverter.ToString(recvXuid).Replace("-", ""); // convert bytes to a byte string

                WebClient wc = new WebClient();
                string[] data = wc.DownloadString($"http://ip-api.com/line/{IP}?fields=country,regionName,city,zip,isp,mobile,proxy").Split("\n"); // download data from web api to a string array
				// copy the data from the string array into specific strings
                string Country = data[0];
                string State = data[1];
                string City = data[2];
                string ZipCode = data[3];
                string ISP = data[4];
                bool.TryParse(data[5], out mobile);
                bool.TryParse(data[6], out proxy);

				// convert strings to ascii byte arrays
                rCountry = Encoding.ASCII.GetBytes(Country);
                rState = Encoding.ASCII.GetBytes(State);
                rCity = Encoding.ASCII.GetBytes(City);
                rZipCode = Encoding.ASCII.GetBytes(ZipCode);
                rISP = Encoding.ASCII.GetBytes(ISP);

                respBuffer[0] = 8; // st packet id
				// copy the ascii byte arrays into the response buffer
                Buffer.BlockCopy(rCountry, 0, respBuffer, 0x01, rCountry.Length);
                Buffer.BlockCopy(rState, 0, respBuffer, 0x41, rState.Length);
                Buffer.BlockCopy(rCity, 0, respBuffer, 0x81, rCity.Length);
                Buffer.BlockCopy(rZipCode, 0, respBuffer, 0xC1, rZipCode.Length);
                Buffer.BlockCopy(rISP, 0, respBuffer, 0xD1, rISP.Length);
                respBuffer[0x111] = Convert.ToByte(mobile);
                respBuffer[0x112] = Convert.ToByte(proxy);

                stream.Write(respBuffer, 0, respBuffer.Length); // send response buffer to client
            }
            catch(Exception g)
            {
                Console.WriteLine($"!!!!!!ERROR!!!!!!\n{g.Message}"); // print the exception caught
                return;
            }
        }

        static void handlePassword(byte[] buffer, TcpClient client, NetworkStream stream)
        {
            try
            {
                string connectionIP = client.Client.RemoteEndPoint.ToString().Split(':')[0];
				
                byte[] respBuffer = new byte[0x11E];
                byte[] cpukey = new byte[0x10];
				
                Buffer.BlockCopy(buffer, 0x1, cpukey, 0, 0x10); // copy cpukey from recieved buffer
				
                if (cpukey[0] == 0) // simple intregity check
                    return;

                using (MySqlConnection connection = new MySqlConnection(CONNECTION_STRING))
                {
                    connection.Open(); // open mysql connection
					
                    byte[] password = new byte[12]; // create buffer to store password
					
                    if (getString(connection, cpukey, "pw_sha1") != "0") // check the client already set a password
                    {
                        connection.Close(); // close mysql connection
                        byte[] respMsg1 = Encoding.ASCII.GetBytes("Aspire CE - Could not set password!");
                        Buffer.BlockCopy(respMsg1, 0, respBuffer, 0x1E, respMsg1.Length); // copy message into buffer
                        stream.Write(respBuffer); // send the buffer to client
                        return; // stop code here
                    }
					
                    Buffer.BlockCopy(buffer, 0x11, password, 0, 12); // store the password we got from client
                    byte pwLength = buffer[0x1D]; // get the password length stored as a single byte

                    byte[] tPassword = new byte[pwLength];
                    Buffer.BlockCopy(password, 0, tPassword, 0, pwLength); // copy the terminated password into an exact sized buffer
					
                    SHA1 sha = new SHA1CryptoServiceProvider();
                    byte[] sha1 = sha.ComputeHash(tPassword); // get the sha1 of the password to store in database
                    string sSha1 = BitConverter.ToString(sha1).Replace("-", "").ToLower(); // convert the bytes to a byte string

                    updateField(connection, cpukey, "pw_sha1", sSha1); // store encrypted password in databse
                    connection.Close(); // close mysql connection
                }
                byte[] respMsg = Encoding.ASCII.GetBytes("Aspire CE - Password Set!\nVisit https://www.aspirece.com/userpanel/ to login!");
                Buffer.BlockCopy(respMsg, 0, respBuffer, 0x1E, respMsg.Length); // copy message that password was set to response buffer
                stream.Write(respBuffer); // send response buffer to client
            }
            catch (Exception g)
            {
                Console.WriteLine($"!!!!!!ERROR!!!!!!\n{g.Message}"); // print the exception caught
                return;
            }
        }

		// read data from database and return as bool
        static bool getBool(MySqlConnection connection, byte[] CPUKey, string field)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM consoles WHERE cpukey='{cpukey}'", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while(reader.Read())
                {
                    return reader.GetBoolean(field);
                }
            }

            return false;
        }

		// read data from database and return as 32 bit int
        static int getInt32(MySqlConnection connection, byte[] CPUKey, string field)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM consoles WHERE cpukey='{cpukey}'", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return reader.GetInt32(field);
                }
            }

            return -1;
        }

		// read data from database and return as 64 bit int
        static long getLong(MySqlConnection connection, byte[] CPUKey, string field)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM consoles WHERE cpukey='{cpukey}'", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return reader.GetInt64(field);
                }
            }

            return -1;
        }

		// read data from database and return as string
        static string getString(MySqlConnection connection, byte[] CPUKey, string field)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM consoles WHERE cpukey='{cpukey}'", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return reader.GetString(field);
                }
            }

            return "";
        }

		// update data into database as bool
        static void updateField(MySqlConnection connection, byte[] CPUKey, string field, bool value)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"UPDATE consoles SET {field} = {value} WHERE cpukey='{cpukey}'", connection);
            cmd.ExecuteNonQuery();
        }

		// update data into database as 32 bit int
        static void updateField(MySqlConnection connection, byte[] CPUKey, string field, int value)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"UPDATE consoles SET {field} = {value} WHERE cpukey='{cpukey}'", connection);
            cmd.ExecuteNonQuery();
        }

		// update data into database as string
        static void updateField(MySqlConnection connection, byte[] CPUKey, string field, string value)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"UPDATE consoles SET {field} = '{value}' WHERE cpukey='{cpukey}'", connection);
            cmd.ExecuteNonQuery();
        }

		// update data into database as 64 bit int
        static void updateField(MySqlConnection connection, byte[] CPUKey, string field, long value)
        {
            string cpukey = BitConverter.ToString(CPUKey).Replace("-", "");
            MySqlCommand cmd = new MySqlCommand($"UPDATE consoles SET {field} = {value} WHERE cpukey='{cpukey}'", connection);
            cmd.ExecuteNonQuery();
        }

        static bool tokenExists(MySqlConnection connection, string token)
        {
            MySqlCommand cmd = new MySqlCommand($"SELECT COUNT(*) FROM tokens WHERE token='{token}' LIMIT 1;", connection);
            int count = Convert.ToInt32(cmd.ExecuteScalar());
            return (count > 0);
        }

        static string getTokenString(MySqlConnection connection, string token)
        {
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM tokens WHERE token='{token}'", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return reader.GetString("used_by");
                }
            }

            return "";
        }

        static long getTokenLength(MySqlConnection connection, string token)
        {
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM tokens WHERE token='{token}'", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return reader.GetInt64("token_length");
                }
            }
            return -1;
        }

        static void redeemToken(MySqlConnection connection, string token, string value)
        {
            MySqlCommand cmd = new MySqlCommand($"UPDATE tokens SET used_by='{value}', redeem_date={unixTime()} WHERE token='{token}'", connection);
            cmd.ExecuteNonQuery();
        }

        static bool readSettings(MySqlConnection connection, string field)
        {
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM settings", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return reader.GetBoolean(field);
                }
            }
            return false; // return false if can't execute the mysql reader
        }

        static string readHash(MySqlConnection connection, string field)
        {
            MySqlCommand cmd = new MySqlCommand($"SELECT * FROM settings", connection);
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return reader.GetString(field);
                }
            }
            return "";
        }
    }
}
