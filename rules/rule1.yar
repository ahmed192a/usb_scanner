rule r1
{
    strings:
        $text = "nourhan"

    condition:
       $text
}