using System.Data;
using CookiesMaster.Utils;

namespace CookiesMaster.Models;

public class LoginData(IDataRecord reader)
{
    public const string Query = "SELECT origin_url, action_url, username_element, username_value, password_element, password_value, submit_element, date_created, scheme, password_type, signon_realm, id FROM logins";
    public string? OriginUrl { get; } = reader.GetString(0);
    public string? ActionUrl { get; } = reader.GetString(1);
    public string? UsernameElement { get; } = reader.GetString(2);
    public string? UsernameValue { get; } = reader.GetString(3);
    public string? PasswordElement { get; } = reader.GetString(4);
    public string? PasswordValue { get; } = reader.GetString(5);
    public string? SubmitElement { get; } = reader.GetString(6);
    public DateTime? DateCreated { get; } = reader.GetInt64(7).DataTimeValue();
    public int? Scheme { get; } = reader.GetInt32(8);
    public int? PasswordType { get; } = reader.GetInt32(9);
    public string? SignonRealm { get; } = reader.GetString(10);
    public int? Id { get; } = reader.GetInt32(11);
    public string? Password { get; set; }


    public override string ToString()
    {
        return $"OriginUrl: {OriginUrl}, ActionUrl: {ActionUrl}, UsernameElement: {UsernameElement}, UsernameValue: {UsernameValue}, PasswordElement: {PasswordElement}, PasswordValue: {PasswordValue.MaxLength(10)}, SubmitElement: {SubmitElement}, DateCreated: {DateCreated}, Scheme: {Scheme}, PasswordType: {PasswordType}, SignonRealm: {SignonRealm}, Id: {Id}";
    }


    public const string Ddl = """
                              CREATE TABLE IF NOT EXISTS logins_decrypt (
                                  origin_url TEXT NOT NULL,
                                  action_url TEXT NOT NULL,
                                  username_element TEXT NOT NULL,
                                  username_value TEXT NOT NULL,
                                  password_element TEXT NOT NULL,
                                  password_value BLOB NOT NULL,
                                  submit_element TEXT NOT NULL,
                                  date_created INTEGER NOT NULL,
                                  scheme INTEGER NOT NULL,
                                  password_type INTEGER NOT NULL,
                                  signon_realm TEXT NOT NULL,
                                  id INTEGER NOT NULL,
                                  password TEXT
                              );
                              """;

    public const string Insert = """
                                 INSERT INTO logins_decrypt (
                                     origin_url,
                                     action_url,
                                     username_element,
                                     username_value,
                                     password_element,
                                     password_value,
                                     submit_element,
                                     date_created,
                                     scheme,
                                     password_type,
                                     signon_realm,
                                     id,
                                     password
                                 ) VALUES (
                                     @origin_url,
                                     @action_url,
                                     @username_element,
                                     @username_value,
                                     @password_element,
                                     @password_value,
                                     @submit_element,
                                     @date_created,
                                     @scheme,
                                     @password_type,
                                     @signon_realm,
                                     @id,
                                     @password
                                 );
                                 """;
}