using System;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Security;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using ServiceConfiguration = Microsoft.IdentityModel.Configuration.ServiceConfiguration;

namespace WCFServiceWebRole
{
    public class CustomServiceHostFactory : ServiceHostFactory
    {
        protected override ServiceHost CreateServiceHost(Type serviceType, Uri[] baseAddresses)
        {
            //All the custom factory does is return a new instance
            //of our custom host class. The bulk of the custom logic should
            //live in the custom host (as opposed to the factory) 
            //for maximum
            //reuse value outside of the IIS/WAS hosting environment.

            return new CustomServiceHost(serviceType, baseAddresses);
        }
    }
}