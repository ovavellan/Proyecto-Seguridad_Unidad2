namespace CookiesMaster.Utils;

public static class Extensions
{
    public static DateTime? DataTimeValue(this long date)
    {
        var epoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        return epoch.AddMicroseconds(date);
    }

    public static string MaxLength(this string? value, int length)
    {
        if (value == null) return "null";
        return value.Length <= length ? value : string.Concat(value.AsSpan(0, length - 3), "...");
    }
}