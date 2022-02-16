rule r4
{
    strings:
        $badvir = "wicked wicked"

    condition:
        $badvir 
}
