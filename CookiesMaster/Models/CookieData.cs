using System.Data;
using CookiesMaster.Utils;

namespace CookiesMaster.Models;

public class CookieData(IDataRecord reader)
{
    public const string Query = "SELECT creation_utc, host_key, name, encrypted_value, path, source_port, source_scheme, is_persistent, value FROM cookies";
    public DateTime? CreationUtc { get; } = reader.GetInt64(0).DataTimeValue();
    public string? HostKey { get; } = reader.GetString(1);
    public string? Name { get; } = reader.GetString(2);
    public string? EncryptedValue { get; } = reader.GetString(3);
    public string? Path { get; } = reader.GetString(4);
    public int? SourcePort { get; } = reader.GetInt32(5);
    public int? SourceScheme { get; } = reader.GetInt32(6);
    public bool IsPersistent { get; set; } = reader.GetBoolean(7);
    public string? Value { get; set; }

    public override string ToString()
    {
        return $"CreationUtc: {CreationUtc}, HostKey: {HostKey}, Name: {Name}, EncryptedValue: {EncryptedValue.MaxLength(10)}, Path: {Path}, SourcePort: {SourcePort}, SourceScheme: {SourceScheme}, IsPersistent: {IsPersistent}, Value: {Value.MaxLength(10)}";
    }

    public const string Ddl = """
                                CREATE TABLE IF NOT EXISTS cookies_decrypt (
                                  creation_utc INTEGER NOT NULL,
                                  host_key TEXT NOT NULL,
                                  name TEXT NOT NULL,
                                  encrypted_value BLOB NOT NULL,
                                  path TEXT NOT NULL,
                                  source_port INTEGER NOT NULL,
                                  source_scheme INTEGER NOT NULL,
                                  value TEXT
                                );
                              """;

    public const string Insert = """
                                 INSERT INTO cookies_decrypt (
                                      creation_utc,
                                      host_key,
                                      name,
                                      encrypted_value,
                                      path,
                                      source_port,
                                      source_scheme,
                                      value
                                  ) VALUES (
                                      @creation_utc,
                                      @host_key,
                                      @name,
                                      @encrypted_value,
                                      @path,
                                      @source_port,
                                      @source_scheme,
                                      @value
                                  );
                                 """;
}