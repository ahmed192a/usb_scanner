rule r5
{
    strings:
        $bad1 = "there"
        $bad2 = "is"
        $bad3 = "nothing"
        $bad4= "holding"
        $bad5="me"
        $bad6="back"

    condition:
        4 of ($bad1,$bad2,$bad3,$bad4,$bad5,$bad6)
}