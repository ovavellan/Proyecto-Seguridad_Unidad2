using static System.Console;

namespace CookiesMaster.Utils;

public static class ConsoleCustom
{
    public static void WriteBoxed(string text, ConsoleColor color)
    {
        var length = text.Length;

        var horizontalBorder = new string('═', length + 8);
        var verticalSpace = new string(' ', 4);
        var verticalBorder = "║" + verticalSpace + text + verticalSpace + "║";

        var colorBefore = ForegroundColor;
        ForegroundColor = color;
        WriteLine("╔{0}╗", horizontalBorder);
        WriteLine(verticalBorder);
        WriteLine("╚{0}╝", horizontalBorder);
        ForegroundColor = colorBefore;
    }

    public static void WriteError(string message, params object?[]? args) => WriteColor(message, ConsoleColor.Red, args);
    public static void WriteSuccess(string message, params object?[]? args) => WriteColor(message, ConsoleColor.Blue, args);
    public static void WriteWarning(string message, params object?[]? args) => WriteColor(message, ConsoleColor.Yellow, args);

    private static void WriteColor(string message, ConsoleColor color, params object?[]? args)
    {
        var colorBefore = ForegroundColor;
        ForegroundColor = color;
        WriteLine(message, args);
        ForegroundColor = colorBefore;
    }
}