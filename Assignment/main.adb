-- Authors: Catherine Jiawen Song 965600, Ziqi Jia 693241

--  Our implementation proves following security properties:
--  The Get, Put, Remove and Lock operations can only ever be performed 
--  when the password manager is in the unlocked state. 
--  We implemented procedures called Execute_xxx (i.e. Execute_Lock) 
--  for each operation and only calls the operation if preconditions are true. 
--  We specified the precondition IsLocked(Manager_Information) = False for all 
--  four operations to ensure that they are only executed if the password manager 
--  is unlocked. This ensures the confidentiality and integrity of the system as 
--  only users who has knowledge of the master pin can access and carry out changes 
--  to the database and master pin. We added the precondition PasswordDatabase.Has_Password_For 
--  for Get and Remove operations to ensure that the operations are not carried out if 
--  the database has no entry for the url in question. This ensures the safety of the system 
--  and prevents from the system from crashing if Put or Remove operations are executed 
--  for an entry that does not exist within the PasswordDatabase. For Put Command we 
--  specified the precondition StoredDatabaseLength(Manager_Information) < PasswordDatabase.Max_Entries 
--  in addition to IsLocked precondition to ensure that the number of database entries stored 
--  currently do not the maximum entries specified. Likewise, this also ensures the safety 
--  of the system and prevents the database from overflowing and causing the system to crash. 
--  
--  The Unlock operation can only ever be performed when the password manager is in the locked state.
--  We have an Execute_Unlock procedure which only calls the procedure Unlock_Manager if the 
--  IsLocked(Manager_Information) and supplied input pin equals to the stored master pin preconditions 
--  are true. We specified the post condition that if Unlock_Manager is executed then the Pin_Input 
--  needs to be equal to the current master pin and that IsLocked(Manager_Information) = False. This 
--  ensures the authentication of the system as only users who knows master pin can unlock the password manager.
--  
--  The Lock operation, when it is performed, should update the master PIN with 
--  the new PIN that is supplied.
--  We have Execute_Lock procedure which only calls the procedure Lock_Manager if the 
--  IsLocked(Manager_Information) precondition is false. We specified post conditions 
--  that if Lock_Manager is executed then the Master Pin needs to be updated to Pin_Input 
--  and IsLocked(Manager_Information) is true. This ensures the authentication of the 
--  system as only users who have unlocked the password manager can update 
--  changes to the master pin and lock the system.
--  
--  The password manager can be in one of two states, either locked or unlocked.
--  We implemented a private record type called information that records the database, 
--  master pin and lock status of the system. Our implementation ensures encapsulation 
--  and allows information hiding as this information cannot be accessed outside 
--  of the PasswordManager package. Is_Locked represents the two states 
--  of the Password Manager and can be only accessed through the Lock_Status function.


pragma SPARK_Mode (On);

with PasswordDatabase;
with MyCommandLine;
with MyString;
with MyStringTokeniser;
with PIN;
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Integer_Text_IO; use Ada.Integer_Text_IO;
with Ada.Characters.Handling; use Ada.Characters.Handling;
with PasswordManager;
with Utility;
procedure Main is

   package Lines is new MyString(Max_MyString_Length => 2048);
   S  : Lines.MyString;
   PM_Information : PasswordManager.Information;
   GETDB : constant String := "get";
   REMDB : constant String := "rem";
   PUTDB : constant String := "put";
   UNLOCK : constant String := "unlock";
   LOCK : constant String := "lock";
   TokensList : MyStringTokeniser.TokenArray(1..5):= (others => (Start => 1, Length => 0));
   NumTokens : Natural;

begin
   -- Program must initiate with 1 Pin input
   if (MyCommandLine.Argument_Count = 1) then
      declare
         Temp_Pin : String := MyCommandLine.Argument(1);
      begin
         -- Pin must meet specified Pin requirements prior to Password Manager
         -- initiation
         if (MyCommandLine.Argument(1)'Length = 4 and
               (for all I in Temp_Pin'Range => Temp_Pin(I)
                >= '0' and Temp_Pin(I) <= '9')) then
            PasswordManager.Init(MyCommandLine.Argument(1), PM_Information);
         else
            Put_Line("Invalid input, program will exit!");
            return;
         end if;
      end;

   else
      Put_Line("Invalid input, program will exit!");
      return;
   end if;

   -- While loop for the system
   while True loop
      -- Checks status of Password Manager
      if (PasswordManager.Lock_Status(PM_Information)) then
         Put("locked>   ");Lines.Get_Line(S);
      else
         Put("unlocked> ");Lines.Get_Line(S);
      end if;

      -- Tokenises input
      MyStringTokeniser.Tokenise(Lines.To_String(S),TokensList,NumTokens);

      -- Checks input command validity and termiantes program if input
      -- does not follow requirements
      if (NumTokens < 1 or NumTokens > 3
          or Lines.To_String(S)'Length < 1
          or Lines.To_String(S)'Length > Utility.Max_Line_Length) then
            Put_Line("Invalid input, program will exit!");
            return;
      else
         declare
            -- Converts command token into string
            Command : String :=
              To_Lower(Lines.To_String(Lines.Substring(S,TokensList(1).Start,
                       TokensList(1).Start+TokensList(1).Length-1)));

         begin
            -- Get Command
            if (Command = GETDB and NumTokens = Utility.Get_Rem_Pin_Length) then
               -- If validity check is met get command is executed
               declare
                  -- Converts Url Token into String
                  TokUrl : String := Lines.To_String
                    (Lines.Substring(S,TokensList(2).Start,
                     TokensList(2).Start+TokensList(2).Length-1));
               begin
                  -- If Url is within required length then get
                  -- execution is called
                  if (TokUrl'Length <= PasswordDatabase.Max_URL_Length) then
                     PasswordManager.Execute_Get_Command
                       (PM_Information,PasswordDatabase.From_String(TokUrl));
                  -- Else the program terminates with error message
                  else
                     Put_Line("Invalid input, program will exit!");
                     return;
                  end if;
               end;


            -- Put Command
            elsif (Command = PUTDB and NumTokens = Utility.Put_Length) then
               declare
                  -- Converts Url Token into String
                  TokUrl : String := Lines.To_String
                    (Lines.Substring(S,TokensList(2).Start,
                     TokensList(2).Start+TokensList(2).Length-1));
                  -- Converts Pwd Token into String
                  TokPwd : String := Lines.To_String
                    (Lines.Substring(S,TokensList(3).Start,
                     TokensList(3).Start+TokensList(3).Length-1));
               begin
                  -- If url and password are within required length then
                  -- put execution is called
                  if (TokUrl'Length <= PasswordDatabase.Max_URL_Length and
                        TokPwd'Length <= PasswordDatabase.Max_Password_Length) then
                     PasswordManager.Execute_Put_Command
                       (PM_Information,PasswordDatabase.From_String(TokUrl),
                        PasswordDatabase.From_String(TokPwd));
                  -- Else the program terminates with error message
                  else
                     Put_Line("Invalid input, program will exit!");
                     return;
                  end if;
               end;

            -- Rem Command
            elsif (Command = REMDB and NumTokens = Utility.Get_Rem_Pin_Length) then
               declare
                  -- Converts Url Token into String
                  TokUrl : String := Lines.To_String
                    (Lines.Substring(S,TokensList(2).Start,
                     TokensList(2).Start+TokensList(2).Length-1));
               begin
                  -- If Url is within required length then command is executed
                  if (TokUrl'Length <= PasswordDatabase.Max_URL_Length) then
                     PasswordManager.Execute_Rem_Command
                       (PM_Information,PasswordDatabase.From_String(TokUrl));
                  -- Else the program terminates with error message
                  else
                     Put_Line("Invalid input, program will exit!");
                     return;
                  end if;
               end;

               -- Unlock Command
            elsif (Command = UNLOCK and NumTokens = Utility.Get_Rem_Pin_Length) then
                  declare
                      -- Converts Pin Token into String
                     TokPin : String := Lines.To_String
                    (Lines.Substring(S,TokensList(2).Start,
                     TokensList(2).Start+TokensList(2).Length - 1));
                  begin
                  -- If Pin validity is met then Password Manager will
                  -- be unlocked
                  if (TokPin'Length = 4 and
                        (for all I in TokPin'Range =>
                           TokPin(I) >= '0' and TokPin(I) <= '9')) then

                     PasswordManager.Execute_Unlock
                       (PM_Information, PIN.From_String(TokPin));
                  -- Else the program terminates with error message
                  else
                     Put_Line("Invalid input, program will exit!");
                     return;
                  end if;
               end;

            -- Lock Command
            elsif(Command = LOCK and NumTokens = Utility.Get_Rem_Pin_Length) then
               declare
                  TokPin : String := Lines.To_String
                    (Lines.Substring(S,TokensList(2).Start,
                     TokensList(2).Start+TokensList(2).Length-1));
               begin
                  -- If validity check is met Lock command is executed
                  if (TokPin'Length = 4 and
                        (for all I in TokPin'Range =>
                           TokPin(I) >= '0' and TokPin(I) <= '9')) then

                        PasswordManager.Execute_Lock(PM_Information,
                                                     PIN.From_String(TokPin));
                  -- Else the program terminates with error message
                  else
                     Put_Line("Invalid input, program will exit!");
                     return;
                  end if;
               end;

               -- Other irregular commands will cause program to print out
               -- error message and terminate
               else
                  Put_Line("Invalid input, program will exit!");
                  return;
            end if;
         end;
      end if;
   end loop;


end Main;
