# froko.Owin.Security.Jwt #

This repo is the source of a NuGet package which enables authentication with Json Web Tokens (JWT) on Owin based windows or web applications. This is particularly useful when you plan to create an API for a web application that's built with JavaScript/Typescript like Angular.

The solution is based on a blog post by Taiseer Joudeh (Bit of Technology) and can be found [here](http://bitoftech.net/2015/02/16/implement-oauth-json-web-tokens-authentication-in-asp-net-web-api-and-identity-2/).



## Prerequisites ##
- An existing Owin based wep API with .NET Framework 4.6.1. Hosting is irrelevant. It can be a console application or an ASP.NET project.

## Usage ##
- Install the NuGet package: `Install-Package froko.Owin.Security.Jwt`
- Add the JWT token authentication to the `AppBuilder` pipeline:

		app.UseOauthWithJwtTokens();
	
	If you are using CORS, please be aware to put the above line before `app.UseCors(...)`. Otherwise it won't work.
	A typical Startup class for a web API could look like this:

		public class Startup
    	{
    	    public void Configuration(IAppBuilder app)
    	    {
    	        app.UseOauthWithJwtTokens();
    	        app.UseCors(CorsOptions.AllowAll);
    	        
    	        var configuration = CreateHttpConfiguration();
    	        app.UseWebApi(configuration);
    	    }
        
    	    private static HttpConfiguration CreateHttpConfiguration()
    	    {
    	        var configuration = new HttpConfiguration();
    	        configuration.MapHttpAttributeRoutes();
    	        configuration.EnableCors(new EnableCorsAttribute("*", "*", "*"));

    	        var jsonFormatter = configuration.Formatters.OfType<JsonMediaTypeFormatter>().First();
    	        jsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();

    	        return configuration;
    	    }
    	}

## Configuration ##
The NuGet package adds the following app settings to your app.config/web.config:

		<appSettings>
    		<add key="Issuer" value="http://localhost" />
    		<add key="AudienceId" value="414e1927a3884f68abc79f7283837fd1" />
    		<add key="AudienceSecret" value="qMCdFDQuF23RV1Y-1Gq9L3cF3VmuFwVbam4fMTdAfpo" />
  		</appSettings>

You may want to change the values of these settings accordingly.

There are multiple overloads of the `UseOauthWithJwtTokens` extensions method:

- `UseOauthWithJwtTokens()` [No parameters]
	
	This is the most simple usage which takes the follwowing predefined assuptions/behaviors:
	- Username and password must match
	- Username is used as role name
	- All origins are allowed
	- Insecure HTTP is allowed
	- Token endpoint is `"/oauth/token"`
	- Token expiration time span is 1 Day

----------

- `UseOauthWithJwtTokens(Func<Username, Password, Task<bool>> verifyUser, Func<Username, ClaimsIdentity, Task> fillClaims)`

	Provides you with the ability to verify the user by its provided username and password. Additionally you can add your own claims (e.g. roles) based on the user's name to the `ClaimsIdentity` object. These two functions are `async` by default.

	Apart from that the following predefined assumptions are still valid:
	- All origins are allowed
	- Insecure HTTP is allowed
	- Token endpoint is `"/oauth/token"`
	- Token expiration time span is 1 Day

----------

- `UseOauthWithJwtTokens(OAuthWithJwtTokens configuration)`

	By deriving and using your own class from the abstract base class `OAuthWithJwtTokens`, you can overwrite every predefined assumption:

		public abstract class OAuthWithJwtTokens
    	{
        	public virtual string Issuer => ConfigurationManager.AppSettings["Issuer"];
			
			public virtual string AudienceId => ConfigurationManager.AppSettings["AudienceId"];

	        public virtual byte[] AudienceSecret => TextEncodings.Base64Url.Decode(ConfigurationManager.AppSettings["AudienceSecret"]);
        
	        public virtual AllowedOrigins AllowedOrigins => AllowedOrigins.All;

        	public virtual bool AllowInsecureHttp => true;

	        public virtual string TokenEndpointPath => "/oauth/token";
			
			public virtual TimeSpan AccessTokenExpireTimeSpan => TimeSpan.FromDays(1);

	        public abstract Task<bool> VerifyCredentials(UserName userName, Password password);

	        public abstract Task FillClaims(UserName userName, ClaimsIdentity identity);
    	}

----------

For convenience and semantic type safety I've implemented 3 helper classes:

- `Username`: Provides the user name. This class is implicitly convertible from and to `string`
- `Password`: Provides the password. This class is implicitly convertible from and to `string`
- `AllowedOrigins`: Provides the allowed origins. This class is implicitly convertible to `string[]`. It has a constructor which takes a list of strings to define allowed origins. Furthermore it has a static builder method called `All` to define all origins. 