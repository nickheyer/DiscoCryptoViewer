<script lang="ts">
  import type { ParsedObject } from '../proto/discocrypto/v1/parser_pb';
  import { cryptoObjectTypeName, objectAccent } from '../utils/format';

  import CertificateView from './x509/CertificateView.svelte';
  import CSRView from './x509/CSRView.svelte';
  import CRLView from './x509/CRLView.svelte';
  import AttributeCertView from './x509/AttributeCertView.svelte';
  import PublicKeyView from './keys/PublicKeyView.svelte';
  import PrivateKeyView from './keys/PrivateKeyView.svelte';
  import DHParamsView from './keys/DHParamsView.svelte';
  import PemFileView from './pem/PemFileView.svelte';
  import PKCS7View from './pkcs/PKCS7View.svelte';
  import PKCS8View from './pkcs/PKCS8View.svelte';
  import PKCS12View from './pkcs/PKCS12View.svelte';
  import TimestampView from './pkcs/TimestampView.svelte';
  import SSHPublicKeyView from './ssh/SSHPublicKeyView.svelte';
  import SSHPrivateKeyView from './ssh/SSHPrivateKeyView.svelte';
  import SSHCertificateView from './ssh/SSHCertificateView.svelte';
  import PGPPublicKeyView from './pgp/PGPPublicKeyView.svelte';
  import PGPPrivateKeyView from './pgp/PGPPrivateKeyView.svelte';
  import PGPSignatureView from './pgp/PGPSignatureView.svelte';
  import JWKView from './jwk/JWKView.svelte';
  import JWKSView from './jwk/JWKSView.svelte';
  import JWTView from './jwk/JWTView.svelte';
  import JWSView from './jwk/JWSView.svelte';
  import JWEView from './jwk/JWEView.svelte';
  import OCSPRequestView from './ocsp/OCSPRequestView.svelte';
  import OCSPResponseView from './ocsp/OCSPResponseView.svelte';
  import SCTView from './ct/SCTView.svelte';

  let { object }: { object: ParsedObject } = $props();

  let accent = $derived(objectAccent(object.object.case ?? ''));
</script>

<div class="dc-object accent-{accent}">
  <div class="dc-object-header">
    <span class="dc-object-type">{cryptoObjectTypeName(object.type)}</span>
    {#if object.label}
      <span class="dc-object-label">{object.label}</span>
    {/if}
  </div>
  <div class="dc-object-body">
    {#if object.object.case === 'certificate'}
      <CertificateView cert={object.object.value} />
    {:else if object.object.case === 'certificateRequest'}
      <CSRView csr={object.object.value} />
    {:else if object.object.case === 'crl'}
      <CRLView crl={object.object.value} />
    {:else if object.object.case === 'attributeCertificate'}
      <AttributeCertView cert={object.object.value} />
    {:else if object.object.case === 'publicKey'}
      <PublicKeyView key={object.object.value} />
    {:else if object.object.case === 'privateKey'}
      <PrivateKeyView key={object.object.value} />
    {:else if object.object.case === 'dhParameters'}
      <DHParamsView params={object.object.value} />
    {:else if object.object.case === 'pemFile'}
      <PemFileView pem={object.object.value} />
    {:else if object.object.case === 'pkcs7'}
      <PKCS7View pkcs7={object.object.value} />
    {:else if object.object.case === 'pkcs8'}
      <PKCS8View info={object.object.value} />
    {:else if object.object.case === 'pkcs8Encrypted'}
      <PKCS8View encrypted={object.object.value} />
    {:else if object.object.case === 'pkcs12'}
      <PKCS12View p12={object.object.value} />
    {:else if object.object.case === 'sshPublicKey'}
      <SSHPublicKeyView key={object.object.value} />
    {:else if object.object.case === 'sshPrivateKey'}
      <SSHPrivateKeyView key={object.object.value} />
    {:else if object.object.case === 'sshCertificate'}
      <SSHCertificateView cert={object.object.value} />
    {:else if object.object.case === 'pgpPublicKey'}
      <PGPPublicKeyView key={object.object.value} />
    {:else if object.object.case === 'pgpPrivateKey'}
      <PGPPrivateKeyView key={object.object.value} />
    {:else if object.object.case === 'pgpSignature'}
      <PGPSignatureView sig={object.object.value} />
    {:else if object.object.case === 'jwk'}
      <JWKView jwk={object.object.value} />
    {:else if object.object.case === 'jwks'}
      <JWKSView jwks={object.object.value} />
    {:else if object.object.case === 'jwt'}
      <JWTView jwt={object.object.value} />
    {:else if object.object.case === 'jws'}
      <JWSView jws={object.object.value} />
    {:else if object.object.case === 'jwe'}
      <JWEView jwe={object.object.value} />
    {:else if object.object.case === 'ocspRequest'}
      <OCSPRequestView request={object.object.value} />
    {:else if object.object.case === 'ocspResponse'}
      <OCSPResponseView response={object.object.value} />
    {:else if object.object.case === 'sct'}
      <SCTView sct={object.object.value} />
    {:else if object.object.case === 'timestampResponse'}
      <TimestampView response={object.object.value} />
    {:else}
      <div style="color: var(--dc-text-dim); padding: 8px">
        Unsupported object type: {object.object.case ?? 'unknown'}
      </div>
    {/if}
  </div>
</div>
