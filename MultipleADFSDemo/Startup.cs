using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MultipleADFSDemo.Startup))]
namespace MultipleADFSDemo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
