using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using MultipleADFSDemo.Models;
using Microsoft.Owin.Security.WsFederation;
using Microsoft.Owin.Security.Cookies;

namespace MultipleADFSDemo.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            var ctx = Request.GetOwinContext();
            if (provider == "Antariksh ADFS")
            {
                ctx.Authentication.Challenge(
                    new AuthenticationProperties
                    {
                        RedirectUri = Url.Action("LoginCallbackAntarikshAdfs", "Account", new { provider })
                    },
                    provider);
            }
            else if (provider == "IndiaUniverse ADFS")
            {
                ctx.Authentication.Challenge(
                    new AuthenticationProperties
                    {
                        RedirectUri = Url.Action("LoginCallbackIndiaUniverseAdfs", "Account", new { provider })
                    },
                    provider);
            }
            return new HttpUnauthorizedResult();
        }

        public ActionResult LoginCallbackAntarikshAdfs(string provider)
        {
            var ctx = Request.GetOwinContext();
            var result = ctx.Authentication.AuthenticateAsync("ExternalCookie").Result;
            ctx.Authentication.SignOut("ExternalCookie");

            if (result != null)
            {
                var claims = result.Identity.Claims.ToList();
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, provider));

                var ci = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);
                ctx.Authentication.SignIn(ci);
            }
            return this.RedirectToAction("About", "Home");
        }

        public ActionResult LoginCallbackIndiaUniverseAdfs(string provider)
        {
            var ctx = Request.GetOwinContext();
            var result = ctx.Authentication.AuthenticateAsync("ExternalCookie").Result;
            ctx.Authentication.SignOut("ExternalCookie");

            if (result != null)
            {
                var claims = result.Identity.Claims.ToList();
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, provider));

                var ci = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);
                ctx.Authentication.SignIn(ci);
            }
            return this.RedirectToAction("About", "Home");
        }

        public ActionResult SignOut()
        {
            var appTypes = HttpContext.GetOwinContext().Authentication.GetAuthenticationTypes().Select(at => at.AuthenticationType).ToArray();
            HttpContext.GetOwinContext().Authentication.SignOut(appTypes);
            
            Request.GetOwinContext().Authentication.SignOut(WsFederationAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
            return this.RedirectToAction("Index", "Home");
        }
    }

    class ChallengeResult : HttpUnauthorizedResult
    {
        private const string XsrfKey = "XsrfId";

        public ChallengeResult(string provider, string redirectUri)
            : this(provider, redirectUri, null)
        {
        }

        public ChallengeResult(string provider, string redirectUri, string userId)
        {
            LoginProvider = provider;
            RedirectUri = redirectUri;
            UserId = userId;
        }

        public string LoginProvider { get; set; }
        public string RedirectUri { get; set; }
        public string UserId { get; set; }

        public override void ExecuteResult(ControllerContext context)
        {
            var properties = new AuthenticationProperties() { RedirectUri = RedirectUri };
            if (UserId != null)
            {
                properties.Dictionary[XsrfKey] = UserId;
            }
            context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);            
        }
    }
    
}