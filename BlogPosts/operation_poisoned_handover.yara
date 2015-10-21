rule callTogether_certificate
{
  meta:
    author = "Fireeye Labs"
    version = "1.0"
    reference_hash = "d08e038d318b94764d199d7a85047637"
    description = "detects binaries signed with the CallTogether certificate"
  strings:
    $serial = {452156C3B3FB0176365BDB5B7715BC4C}
    $o = "CallTogether, Inc."
  condition:
    $serial and $o
}

rule qti_certificate
{
    meta:
        author = "Fireeye Labs"
        reference_hash = "cfa3e3471430a0096a4e7ea2e3da6195"
        description = "detects binaries signed with the QTI International Inc certificate"   
    strings:
        $cn = "QTI International Inc"
        $serial = { 2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9 }
    condition:
        $cn and $serial
}
