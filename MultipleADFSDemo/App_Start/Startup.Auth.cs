using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.WsFederation;
using Owin;

namespace MultipleADFSDemo
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Active,                
                LoginPath = new PathString("/Account/Login")
            });
            // Use a cookie to temporarily store information about a user logging in with a third party login provider
            //app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // these two lines of code are needed if you are using any of the external authentication middleware
            app.Properties["Microsoft.Owin.Security.Constants.DefaultSignInAsAuthenticationType"] = "ExternalCookie";
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "ExternalCookie",
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive
            });

            //configure Antariksh ADFS middleware
            var antarikshADFS = new WsFederationAuthenticationOptions
            {
                MetadataAddress = "https://antariksh.cloudapp.net/FederationMetadata/2007-06/FederationMetadata.xml",
                AuthenticationType = "Antariksh ADFS",
                Caption = "Antariksh Domain",
                BackchannelCertificateValidator = null,
                //localhost
                Wreply = "https://localhost:44314/Account/LoginCallbackAntarikshAdfs",
                Wtrealm = "https://localhost:44314/Account/LoginCallbackAntarikshAdfs"
            };

            //configure IndiaUniverse ADFS middleware
            var indiaUniverseADFS = new WsFederationAuthenticationOptions
            {
                MetadataAddress = "https://indiauniverse.cloudapp.net/FederationMetadata/2007-06/FederationMetadata.xml",
                AuthenticationType = "IndiaUniverse ADFS",
                Caption = "India Universe Domain",
                BackchannelCertificateValidator = null,
                //localhost
                Wreply = "https://localhost:44314/Account/LoginCallbackIndiaUniverseAdfs",
                Wtrealm = "https://localhost:44314/Account/LoginCallbackIndiaUniverseAdfs"
            };
            
            app.Map("/Account", configuration =>
            {
                configuration.UseWsFederationAuthentication(antarikshADFS);
                configuration.UseWsFederationAuthentication(indiaUniverseADFS);
            });
        }
    }
}