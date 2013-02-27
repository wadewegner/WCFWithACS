using System.ServiceModel;
using System.ServiceModel.Channels;
using Microsoft.IdentityModel.Protocols.WSTrust.Bindings;

namespace WCFServiceWebRole
{
    public static class Bindings
    {
        public static Binding CreateServiceBinding(string acsCertificateEndpoint)
        {
            var binding = new IssuedTokenWSTrustBinding(CreateAcsCertificateBinding(), new EndpointAddress(acsCertificateEndpoint));

            return binding;
        }

        public static Binding CreateAcsCertificateBinding()
        {
            return new CertificateWSTrustBinding(SecurityMode.TransportWithMessageCredential);
        }
    }
}