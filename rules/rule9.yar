rule r9
{
    strings:
        $a = "i'm virus"

    condition:
        $a
}

rule r9dash
{
    strings:
        $a = "being virused is okay"

    condition:
        $a and r9
}