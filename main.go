package main

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "sync"
)

func main() {
    // Read the certificate file content
    fc, err := ioutil.ReadFile("spring.io.pem")
    if err != nil {
        log.Printf("Failed to read certificate file: %s\n", err)
        return
    }

    // Decode the PEM file
    block, _ := pem.Decode(fc)
    if block == nil {
        log.Println("Failed to decode certificate data")
        return
    }

    // Parse the certificate data
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Printf("Failed to parse certificate data: %s\n", err)
        return
    }

    // Retrieve the CRL URLs
    crlUrls := cert.CRLDistributionPoints

    if crlUrls == nil || len(crlUrls) == 0 {
        log.Println("Unable to check certificate revocation status. No CRL URL defined.")
        return
    }

    // Now let's check the certificate validity
    canCheck := false // Flag indicating whether or not we're able to check for revocation.
    revoked := false // Flag indicating whether or not a certificate is revoked.

    for _, url := range crlUrls {
        log.Printf("Downloading CRL from %s.\n", url)

        // Let's download the crl
        resp, err := http.Get(url)
        if err != nil {
            log.Printf("Failed to download CRL from %s. Skipping this URL.\n", err)
            continue
        }

        // Download successful, read the body
        data, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            log.Printf("Failed to read response body %s. Skipping this URL.\n", err)
            continue
        }

        // Close the connection
        _ = resp.Body.Close()

        // Parse the CRL data
        crl, err := x509.ParseCRL(data)
        if err != nil {
            log.Printf("Failed to parse CRL data: %s. Skipping this URL.\n", err)
            continue
        }

        // Now check the certificate status against the CRL
        certSn := cert.SerialNumber
        revokedCerts := crl.TBSCertList.RevokedCertificates
        wg := sync.WaitGroup{}

        for _, revokedCert := range revokedCerts {
            revokedSn := revokedCert.SerialNumber

            // Spawn a new go-routine to speed-up the checking. Helpful for CRL that contains
            // a lot of items. You might want to limit the number of go-routines based on your
            // circumstances.
            go func() {
                wg.Add(1)
                if certSn.Cmp(revokedSn) == 0 {
                    // The certificate is revoked since the serial number is inside the CRL
                    revoked = true
                }
                wg.Done()
            }()
        }

        wg.Wait()
        canCheck = true
        break
    }

    if !canCheck {
        fmt.Println("Certificate status: Unknown.")
    } else {
        fmt.Printf("Certificate revoked: %v\n", revoked)
    }
}
