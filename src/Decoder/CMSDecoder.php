<?php

namespace FatturaElettronicaPhp\FatturaElettronica\Decoder;

use app\components\Utility;
use FatturaElettronicaPhp\FatturaElettronica\Contracts\DigitalDocumentDecodeInterface;
use SimpleXMLElement;

class CMSDecoder implements DigitalDocumentDecodeInterface
{

    public function decode(string $filePath): ?SimpleXMLElement
    {
        $xmlPath = tempnam(sys_get_temp_dir(), basename($filePath));

        $p7mFilePath = $this->convertFromDERtoSMIMEFormat($filePath);

        $exitCode = 0;
        $output = [];

        if (openssl_pkcs7_verify($p7mFilePath, PKCS7_NOVERIFY, $filePath, [__DIR__ . '/ca.pem'], __DIR__ . '/ca.pem', $xmlPath) !== 1) {
            exec("openssl cms -verify -in $filePath -inform DER -noverify -out $xmlPath", $output, $exitCode);
            if ($exitCode !== 0) {
                exec("openssl smime -verify -in $filePath - -inform DER -noverify -out $xmlPath", $output, $exitCode);
                if ($exitCode !== 0) {
                    return null;
                }
            }
        }

        return (new XMLDecoder())->decode($xmlPath);
    }

    protected function convertFromDERtoSMIMEFormat(string $file): string
    {
        $pemPath = tempnam(sys_get_temp_dir(), basename($file));
        $to = <<<TXT
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"
Content-Transfer-Encoding: base64
\n
TXT;
        $from = file_get_contents($file);
        if (!$this->is_base64($from)) {
            $from = base64_encode($from);
        }
        $to .= chunk_split($from);
        file_put_contents($pemPath, $to);


        return $pemPath;
    }

    protected function is_base64($s)
    {
        return (bool)preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $s);
    }
}
