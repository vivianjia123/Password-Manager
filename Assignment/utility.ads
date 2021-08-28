with MyCommandLine;
with MyStringTokeniser;
with PasswordDatabase;

-- utility is a helper function with the aim to reduce code repetition within
-- the main file
package Utility with SPARK_Mode is

   Max_Line_Length : constant Natural := 2048;
   Put_Length : constant Natural := 3;
   Get_Rem_Pin_Length : constant Natural := 2;
   Max_Command_Length : constant Natural := 3;

end Utility;
