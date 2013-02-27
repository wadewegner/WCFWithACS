using System;
using System.Configuration;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using WCFServiceWebRole;

namespace WCFClient
{
    class Program
    {
        static void Main(string[] args)
        {
            int userInputString = 1;
            Console.WriteLine();

            string acsUsernameEndpoint = String.Format("https://{0}.{1}/v2/wstrust/13/username", AccessControlNamespace, AccessControlHostName);

            ChannelFactory<IService1> stringServiceFactory = CreateChannelFactory(acsUsernameEndpoint, ServiceAddress);
            IService1 stringService = stringServiceFactory.CreateChannel();
            ICommunicationObject channel = (ICommunicationObject)stringService;

            string outputString = stringService.GetData(userInputString);

            Console.WriteLine("Service responded with: " + outputString);
            Console.WriteLine();
            Console.WriteLine("Press <ENTER> to exit");
            Console.ReadLine();

            channel.Close();
        }

        static string AccessControlHostName = ConfigurationManager.AppSettings.Get("AccessControlHostName");
        static string AccessControlNamespace = ConfigurationManager.AppSettings.Get("AccessControlNamespace");

        static string ServiceAddress = ConfigurationManager.AppSettings.Get("ServiceAddress");
        static string ServiceCertificateFilePath = ConfigurationManager.AppSettings.Get("ServiceCertificateFilePath");

        static string ClientCertificateFilePath = ConfigurationManager.AppSettings.Get("ClientCertificateFilePath");
        static string ClientCertificatePassword = ConfigurationManager.AppSettings.Get("ClientCertificatePassword");

        private static ChannelFactory<IService1> CreateChannelFactory(string acsEndpoint, string serviceEndpoint)
        {
            //
            // The WCF service endpoint host name may not match the service certificate subject.
            // By default, the host name is 'localhost' and the certificate subject is 'WcfServiceCertificate'.
            // Create a DNS Endpoint identity to match WcfServiceCertificate.
            //
            EndpointAddress serviceEndpointAddress = new EndpointAddress(new Uri(serviceEndpoint),
                                                                          EndpointIdentity.CreateDnsIdentity(GetServiceCertificateSubjectName()),
                                                                          new AddressHeaderCollection());

            ChannelFactory<IService1> stringServiceFactory = new ChannelFactory<IService1>(Bindings.CreateServiceBinding(acsEndpoint), serviceEndpointAddress);
            
            // Set the service credentials and disable certificate validation to work with sample certificates
            stringServiceFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            stringServiceFactory.Credentials.ServiceCertificate.DefaultCertificate = GetServiceCertificate();

            // Set the client credentials.
            stringServiceFactory.Credentials.ClientCertificate.Certificate = GetClientCertificateWithPrivateKey();




            return stringServiceFactory;
        }
        private static X509Certificate2 GetClientCertificateWithPrivateKey()
        {
            return new X509Certificate2(ClientCertificateFilePath, ClientCertificatePassword);
        }

        private static X509Certificate2 GetServiceCertificate()
        {
            return new X509Certificate2(ServiceCertificateFilePath);
        }

        private static string GetServiceCertificateSubjectName()
        {
            const string cnPrefix = "CN=";
            string subjectFullName = GetServiceCertificate().Subject;
            Debug.Assert(subjectFullName.StartsWith(cnPrefix));
            return subjectFullName.Substring(cnPrefix.Length);
        }

    }
}
