using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

class Program
{
    #region RSA

    static readonly int RSA_KEY_SIZE = 2048;

    static readonly int SHORT_MAX = short.MaxValue;

    static readonly int DELAY_SECONDS = 20;

    static string GetRSAParametersString(RSAParameters parameters)
    {
        string result = "";
        using (var sw = new System.IO.StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, parameters);
            result = sw.ToString();
        }
        return result;
    }

    static RSAParameters GetRSAParameters(string keyString)
    {
        RSAParameters parameters;
        using (var sr = new System.IO.StringReader(keyString))
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            parameters = (RSAParameters)xs.Deserialize(sr);
        }
        return parameters;
    }

    static void GenerateRSAKey(out string privateKey, out string publicKey)
    {
        using (var csp = new RSACryptoServiceProvider(RSA_KEY_SIZE))
        {
            privateKey = GetRSAParametersString(csp.ExportParameters(true));
            publicKey = GetRSAParametersString(csp.ExportParameters(false));
        }
    }

    #endregion

    #region Token generator using timestamp

    static int GetCurrentUnixTimestamp()
    {
        return (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
    }

    static int GetToken(int timestamp)
    {
        return (timestamp / DELAY_SECONDS) % SHORT_MAX;
    }

    static void GenerateKey(out int timestamp, out int token)
    {
        timestamp = GetCurrentUnixTimestamp();
        token = GetToken(timestamp);
    }

    #endregion

    #region Server side

    static void Decrypt(string privateKey, string cipherText, out int timestamp, out int token)
    {
        using (var csp = new RSACryptoServiceProvider())
        {
            csp.ImportParameters(GetRSAParameters(privateKey));
            var bytesCipherText = Convert.FromBase64String(cipherText);
            var bytesPlainText = csp.Decrypt(bytesCipherText, false);
            var plainText = System.Text.Encoding.Unicode.GetString(bytesPlainText);
            var splitedPlainText = plainText.Split(',');
            timestamp = int.Parse(splitedPlainText[0]);
            token = int.Parse(splitedPlainText[1]);
        }
    }

    static bool CheckKeyValid(int timestamp, int token)
    {
        var currentTimestamp = GetCurrentUnixTimestamp();
        if (currentTimestamp - timestamp > DELAY_SECONDS)
        {
            return false;
        }
        return token == GetToken(currentTimestamp);
    }

    #endregion

    #region Client side

    static void Encrypt(string publicKey, int timestamp, int token, out string cipherText)
    {
        using (var csp = new RSACryptoServiceProvider())
        {
            csp.ImportParameters(GetRSAParameters(publicKey));
            var plainText = timestamp.ToString() + "," + token.ToString();
            var bytesPlainText = System.Text.Encoding.Unicode.GetBytes(plainText);
            var bytesCipherText = csp.Encrypt(bytesPlainText, false);
            cipherText = Convert.ToBase64String(bytesCipherText);
        }
    }

    #endregion

    #region Testing

    static void ServerProcess(string privateKey, string receivedData, out bool passed)
    {
        try
        {
            int timestamp, token;
            Decrypt(privateKey, receivedData, out timestamp, out token);
            passed = CheckKeyValid(timestamp, token);
        }
        catch (Exception ex)
        {
            passed = false;
        }
    }

    static void ClientProcess(string publicKey, out string requestData)
    {
        int timestamp, token;
        GenerateKey(out timestamp, out token);
        Encrypt(publicKey, timestamp, token, out requestData);
    }

    // Case 1: Client send a valid key to Server
    static void TestCase1()
    {
        Console.WriteLine("Testing Case 1: Client send a valid key to Server...");
        string privateKey, publicKey;
        GenerateRSAKey(out privateKey, out publicKey);

        string data;
        ClientProcess(publicKey, out data);

        bool passed;
        ServerProcess(privateKey, data, out passed);
        Console.WriteLine("Case 1: " + passed.ToString());
    }

    // Case 2: Client send a invalid key to Server after DELAY_SECONDS / 2 seconds.
    static void TestCase2()
    {
        Console.WriteLine("Testing Case 2: Client send a invalid key to Server after DELAY_SECONDS / 2 seconds...");
        string privateKey, publicKey;
        GenerateRSAKey(out privateKey, out publicKey);

        string data;
        ClientProcess(publicKey, out data);

        Thread.Sleep((DELAY_SECONDS / 2) * 1000);

        bool passed;
        ServerProcess(privateKey, data, out passed);
        Console.WriteLine("Case 2: " + passed.ToString());
    }

    // Case 3: Client send a invalid key to Server after DELAY_SECONDS.
    static void TestCase3()
    {
        Console.WriteLine("Testing Case 3: Client send a invalid key to Server after DELAY_SECONDS...");
        string privateKey, publicKey;
        GenerateRSAKey(out privateKey, out publicKey);

        string data;
        ClientProcess(publicKey, out data);

        Thread.Sleep(DELAY_SECONDS * 1000);

        bool passed;
        ServerProcess(privateKey, data, out passed);
        Console.WriteLine("Case 3: " + (passed ^ true).ToString());
    }

    // Case 4: Client send a invalid key to server, using another RSA key to decrypt data.
    static void TestCase4()
    {
        Console.WriteLine("Testing Case 4: Client send a invalid key to server, using another RSA key to decrypt data...");
        string privateKey, publicKey;
        GenerateRSAKey(out privateKey, out publicKey);

        string privateKey1, publicKey1;
        GenerateRSAKey(out privateKey1, out publicKey1);

        string data;
        ClientProcess(publicKey1, out data);

        bool passed;
        ServerProcess(privateKey, data, out passed);
        Console.WriteLine("Case 4: " + (passed ^ true).ToString());
    }

    #endregion

    static void Main(string[] args)
    {
        TestCase1();
        TestCase2();
        TestCase3();
        TestCase4();
        Console.ReadLine();
    }
}
