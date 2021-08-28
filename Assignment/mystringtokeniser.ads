with Ada.Characters.Latin_1;

package MyStringTokeniser with SPARK_Mode is

   type TokenExtent is record
      Start : Positive;
      Length : Natural;
   end record;

   type TokenArray is array(Positive range <>) of TokenExtent;

   function Is_Whitespace(Ch : Character) return Boolean is
     (Ch = ' ' or Ch = Ada.Characters.Latin_1.LF or
        Ch = Ada.Characters.Latin_1.HT);

   procedure Tokenise(S : in String; Tokens : in out TokenArray; Count : out Natural) with


     Pre => (if S'Length > 0 then S'First <= S'Last) and Tokens'First <= Tokens'Last,
   -- The number of tokens should be equal or less than the number of
   -- elements in Tokens array. This is necessary as it prevents index from
   -- going out of bounds when looping through the Tokens array because
   -- the last element is defined by the Tokens'First (index of first element)
   -- added to Count-1 and if Count is greater than length of array
   -- then Index used to loop through the array may access memory
   -- beyond the array simiarly S'Last - Tokens(Index).Start is an overflow
   -- check which may fail because the index is out of bounds
     Post =>  Count <= Tokens'Length and

     (for all Index in Tokens'First..Tokens'First+(Count-1) =>

       -- The Starting Index of the token should be equal or more than the
      -- starting index of the string. This is necessary because if the
      -- starting index of the token is less than the starting index of
      -- the string then the token may not be within the bounds of the string
      -- i.e. memory before the array is accessed. Hence array index check
      -- will fail as the token is outside the array and overflow
      -- check may also fail because the token length would be undetermined
      -- and could be greater than S'Last - Tokens(Index).Start
        (Tokens(Index).Start >= S'First and

         -- This checks length of the token is at least 1. This is necessary
         -- because if the token is length or less then the token accessed
         -- could be outside the array which means array index check fails
         -- it's likely overflow check will also fail as a result due to
         -- access of undetermined/unauthorised memory
           Tokens(Index).Length > 0) and then

        -- This checks that the last index of the Token is within the bounds
        -- of the string (there is no overflow occurring)
        -- this is necessary as it prevents the token from being
        -- read out of the bounds of the string S causing overflow
            Tokens(Index).Length-1 <= S'Last - Tokens(Index).Start);

end MyStringTokeniser;




