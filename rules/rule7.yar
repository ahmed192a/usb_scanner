rule r7
    {
        strings:
           $hex_string = { F4 23 [4-6] 62 B4 }

        condition:
           $hex_string
    }