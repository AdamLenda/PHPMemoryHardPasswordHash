<?php

class MemoryHardPasswordHash
{
    /**
     * This function uses hash functions and the salt and password as seeds to create a hex string that is 1MB in
     * length. It then uses values from that string to return a 'hashed password' that cannot be cracked using Password
     * Rainbow Tables or GPU hash guessing functions. Uses of this function have averaged less than 1 second in testing
     * so far.
     * @param $salt
     * @param $password
     * @param $hashLength
     * @return string
     *
     * Example Usage:
     * $password = 'ABCDEF';
     * $salt = hex2bin('e869f431de01d1ef2485069b1a83fbf0ec3609f41272e678e6e53156d5be6216');
     * $mhph = new \UtilitiesBundle\MemoryHardPasswordHash();
     * echo $mhph->hash($salt, $password, 64);
     */
    public function hash($salt, $password, $hashLength)
    {
        /*
         * Generate Salt
         */
        //$userModel->setSalt(openssl_random_pseudo_bytes(32));
        $saltString = bin2hex($salt);

        /*
         * Hash Password
         */
        $buffer = hash('sha512', $saltString.$password);

        do {
            $bufferLength = strlen($buffer);
            /*
             * get the last 6 hex characters and convert them to an integer. We then mod that number by the buffer
             * length, because the remainder will be a value between 0 and $bufferLength.
             */
            $offset = hexdec(substr($buffer, $bufferLength-6))%$bufferLength;
            /*
             * We use the offset we just calculated to jump to that position in the buffer and read out the next 6 hex
             * characters. If we run out characters in the buffer before getting the number we need, we wrap around
             * and read the remaining characters from the start of the buffer. Then we convert that 6 place hex string
             * an integer.
             */
            $multiplier = substr($buffer, $offset, 6);
            $multiplierLength = strlen($multiplier);
            if ($multiplierLength < 6) {
                $multiplier .= substr($buffer, 0, 6-$multiplierLength);
            }
            $multiplier = hexdec($multiplier);

            /*
             * We now multiply our original offset value by the multiplier value we just looked up. We then mod that
             * number by the length of the buffer. The result is our offset to use for reading in values from the buffer
             * which will then be hashed and added to the end of the buffer.
             */
            $offset = ($multiplier * $offset) % $bufferLength;
            $subString = substr($buffer, $offset, 64);
            $subLength = strlen($subString);
            if ($subLength < 64) {
                $subString .= substr($buffer, 0, 64 - $subLength);
            }
            //echo "Used offset: ".$offset."\n";
            /*
             * We append the newly created hash to the end of our buffer
             */
            $buffer .= hash('sha512', $subString);
            /*
             * We repeat this process until we have a buffer 1 MB in size.
             */
        } while (strlen($buffer) < 1048192);

        /*
         * Now we pull out our password 'hash' by taking $hashLength characters out of the huge string we've created.
         * Because our hash became less predictable the longer it grew, we do this by taking the last character
         * from the end of the buffer first. Then we work our way back from there. Each time we use the last character
         * we retrieved to offset the next character used and thus add additional unpredictability to the next character
         * selected.
         */
        $hashedPassword = '';
        $i = 0;
        $last = 0;
        $bufferLength = strlen($buffer);
        while (strlen($hashedPassword) < $hashLength) {
            $index = $bufferLength - ($hashLength * $i + $last) -1;
            //in case we somehow manage to wrap back around, then add bufferLength to index until it is > 0 again
            while ($index < 0) {
                $index += $bufferLength;
            }

            $char = $buffer[$index];
            $hashedPassword .= $char;
            $last = hexdec('0'.$char);
            $i++;
        }
        /*
         * After doing all of that work we've now setup a password hash where even if it was compromised it could not
         * be reversed or guessed using either GPU hash acceleration methods or rainbow tables
         */
        return $hashedPassword;
    }
}
