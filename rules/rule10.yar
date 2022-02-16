rule r10
{
    strings:
        $a = "closer!"

    condition:
        $a
}

rule r10dash
{
    strings:
        $a = "halsey"

    condition:
        $a
}

