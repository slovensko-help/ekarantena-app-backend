using MediatR;
using Microsoft.EntityFrameworkCore;
using Sygic.Corona.Domain;
using Sygic.Corona.Domain.Common;
using Sygic.Corona.Infrastructure;
using Sygic.Corona.Infrastructure.Services.AndroidAttestation;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sygic.Corona.Application.Commands
{
    public class VerifyProfileCommandHandler : AsyncRequestHandler<VerifyProfileCommand>
    {
        private readonly CoronaContext context;
        private readonly IRepository repository;
        private readonly IAndroidAttestation androidAttestation;

        public VerifyProfileCommandHandler(CoronaContext context, IRepository repository, IAndroidAttestation androidAttestation)
        {
            this.context = context ?? throw new ArgumentNullException(nameof(context));
            this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
            this.androidAttestation = androidAttestation ?? throw new ArgumentNullException(nameof(androidAttestation));
        }

        protected override async Task Handle(VerifyProfileCommand request, CancellationToken cancellationToken)
        {
            var profile = await repository.GetProfileAsync(request.ProfileId, request.DeviceId, cancellationToken);
            if (profile == null)
            {
                throw new DomainException("Profile not found");
            }

            var now = DateTime.UtcNow;
            var nonce = await context.PushNonces.SingleOrDefaultAsync(x => x.Id == profile.PushToken 
                    && x.ExpiredOn > DateTime.UtcNow, cancellationToken);
            if (nonce?.Body != request.Nonce)
            {
                throw new DomainException("Nonce not found or expired");
            }

            if (profile.ClientInfo.OperationSystem == Platform.Android)
            {
                var attestation = androidAttestation.ParseAndVerify(request.SignedAttestationStatement);

                if (attestation == null || !attestation.BasicIntegrity || !attestation.CtsProfileMatch)
                {
                    throw new DomainException("Device isn't attested");
                }
                var certDigest = new byte[] {0x80, 0xc0, 0xdc, 0x5c, 0x6f, 0x43, 0xd4, 0x97, 0xc4, 0x5a, 0xed, 0x7e, 0x36, 0x98, 0x8a, 0xbe, 0x48, 0xd5, 0xfd, 0xcc, 0xbb, 0xfa, 0xbb, 0xbf, 0x87, 0x86, 0x93, 0x1e, 0x59, 0xdd, 0x1d, 0xaf};
                if (attestation.ApkPackageName != "sk.nczi.ekarantena" || !certDigest.SequenceEqual(attestation.ApkCertificateDigestSha256))
                {
                    throw new DomainException("Device is not using the legitimate app");
                }
            }

            profile.AssignCovidPass(request.CovidPass);
            profile.AssignPublicKey(request.PublicKey);
            profile.Verify();

            await context.SaveChangesAsync(cancellationToken);
        }
    }
}
