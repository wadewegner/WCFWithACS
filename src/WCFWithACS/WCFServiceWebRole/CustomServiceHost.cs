using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Web;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

using Microsoft.IdentityModel.Configuration;
using ServiceConfiguration = Microsoft.IdentityModel.Configuration.ServiceConfiguration;


namespace WCFServiceWebRole
{
    public class CustomServiceHost : ServiceHost
    {
        static string AccessControlHostName = ConfigurationManager.AppSettings.Get("AccessControlHostName");
        static string AccessControlNamespace = ConfigurationManager.AppSettings.Get("AccessControlNamespace");
        static string AccessControlSigningCertificateFilePath = ConfigurationManager.AppSettings.Get("AccessControlSigningCertificateFilePath");
        static string ServiceAddress = ConfigurationManager.AppSettings.Get("ServiceAddress");
        static string ServiceCertificateFilePath = ConfigurationManager.AppSettings.Get("ServiceCertificateFilePath");
        static string ServiceCertificatePassword = ConfigurationManager.AppSettings.Get("ServiceCertificatePassword");

        private static X509Certificate2 GetAcsSigningCertificate()
        {
            return new X509Certificate2(AccessControlSigningCertificateFilePath);
        }

        private static X509Certificate2 GetServiceCertificateWithPrivateKey()
        {
            return new X509Certificate2(ServiceCertificateFilePath, ServiceCertificatePassword);
        }

        public CustomServiceHost(Type serviceType, params Uri[] baseAddresses)
            : base(serviceType, baseAddresses)
        {

            string acsUsernameEndpoint = String.Format("https://{0}.{1}/v2/wstrust/13/username", AccessControlNamespace, AccessControlHostName);

            ServiceHost rpHost = new ServiceHost(typeof(Service1));

            rpHost.Credentials.ServiceCertificate.Certificate = GetServiceCertificateWithPrivateKey();

            rpHost.AddServiceEndpoint(typeof(IService1),
                                       Bindings.CreateServiceBinding(acsUsernameEndpoint),
                                       ServiceAddress);

            //
            // This must be called after all WCF settings are set on the service host so the
            // Windows Identity Foundation token handlers can pick up the relevant settings.
            //
            ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
            serviceConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;

            // Accept ACS signing certificate as Issuer.
            serviceConfiguration.IssuerNameRegistry = new X509IssuerNameRegistry(GetAcsSigningCertificate().SubjectName.Name);

            // Add the SAML 2.0 token handler.
            serviceConfiguration.SecurityTokenHandlers.AddOrReplace(new Saml2SecurityTokenHandler());

            // Add the address of this service to the allowed audiences.
            serviceConfiguration.SecurityTokenHandlers.Configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(ServiceAddress));

            FederatedServiceCredentials.ConfigureServiceHost(rpHost, serviceConfiguration);

        }

        //private static ServiceHost CreateWcfServiceHost()
        //{
        //    string acsUsernameEndpoint = String.Format("https://{0}.{1}/v2/wstrust/13/username", AccessControlNamespace, AccessControlHostName);

        //    ServiceHost rpHost = new ServiceHost(typeof(Service1));

        //    rpHost.Credentials.ServiceCertificate.Certificate = GetServiceCertificateWithPrivateKey();

        //    rpHost.AddServiceEndpoint(typeof(IService1),
        //                               Bindings.CreateServiceBinding(acsUsernameEndpoint),
        //                               ServiceAddress);

        //    //
        //    // This must be called after all WCF settings are set on the service host so the
        //    // Windows Identity Foundation token handlers can pick up the relevant settings.
        //    //
        //    ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
        //    serviceConfiguration.CertificateValidationMode = X509CertificateValidationMode.None;

        //    // Accept ACS signing certificate as Issuer.
        //    serviceConfiguration.IssuerNameRegistry = new X509IssuerNameRegistry(GetAcsSigningCertificate().SubjectName.Name);

        //    // Add the SAML 2.0 token handler.
        //    serviceConfiguration.SecurityTokenHandlers.AddOrReplace(new Saml2SecurityTokenHandler());

        //    // Add the address of this service to the allowed audiences.
        //    serviceConfiguration.SecurityTokenHandlers.Configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri(ServiceAddress));

        //    FederatedServiceCredentials.ConfigureServiceHost(rpHost, serviceConfiguration);

        //    return rpHost;
        //}


        //Overriding ApplyConfiguration() allows us to 
        //alter the ServiceDescription prior to opening
        //the service host. 
        protected override void ApplyConfiguration()
        {
            //First, we call base.ApplyConfiguration()
            //to read any configuration that was provided for
            //the service we're hosting. After this call,
            //this.Description describes the service
            //as it was configured.
            base.ApplyConfiguration();

            //(rest of implementation elided for clarity)
        }
    }
}