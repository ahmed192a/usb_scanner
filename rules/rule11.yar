

rule Rule1
{
    strings:
        $text_string = "virus"

    condition:
       $text_string
}


