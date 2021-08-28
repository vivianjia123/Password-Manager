with Ada.Text_IO; use Ada.Text_IO;
with Ada.Containers; use Ada.Containers;
with Ada.Characters; use Ada.Characters;
with PIN;
with PasswordDatabase;

package body PasswordManager with SPARK_Mode is

   -- Initiates the Password Manager
   procedure Init(Pin_Input : in String;
                  Manager_Information : out Information) is
   begin
      -- Sets the Master Pin and Password Manager state to Locked
      -- also initates the database
         Manager_Information.Master_Pin := PIN.From_String(Pin_Input);
         Manager_Information.Is_Locked := True;
         PasswordDatabase.Init(Manager_Information.Master_Database);
   end;

   -- Determines current lock status of Password Manager
   function Lock_Status(Manager_Information: in Information) return Boolean is
   begin
      if(Manager_Information.Is_Locked = True) then
         return True;
      end if;
      return False;
   end;

   -- Only executes Unlock_Manager if the current state is unlocked
   procedure Execute_Unlock(Manager_Information : in out Information;
                            Pin_Input : in PIN.PIN) is
   begin
      if (PIN."="(Manager_Information.Master_Pin,Pin_Input)
          and Manager_Information.Is_Locked) then
         Unlock_Manager(Manager_Information, Pin_Input);
      end if;
   end;

   -- Changes Password Manager State to Unlocked
   procedure Unlock_Manager(Manager_Information : in out Information;
                            Pin_Input : in PIN.PIN) is
   begin
      -- Password Manager is unlocked
      Manager_Information.Is_Locked := False;
   end;

   -- Only executes Lock_Manager if the current state is unlocked
   procedure Execute_Lock(Manager_Information : in out Information;
                          Pin_Input : in PIN.PIN) is
   begin
      if (Manager_Information.Is_Locked= False) then
         Lock_Manager(Manager_Information, Pin_Input);
      end if;
   end;

   -- Changes Password Manager State to Locked
   procedure Lock_Manager(Manager_Information : in out Information;
                          Pin_Input : in PIN.PIN) is
   begin
      -- Password Manager is set to locked and MasterPin is set to
      -- Pin supplied by user
         Manager_Information.Master_Pin := Pin_Input;
         Manager_Information.Is_Locked := True;
   end;

   -- Only executes Get Command if requirements are met
   procedure Execute_Get_Command(Manager_Information : in Information;
                                 Input_Url : in PasswordDatabase.URL) is
   begin
       -- If Password Manager is unlocked and Database contains entry
      -- for the Url then call Put Command
      if (PasswordDatabase.Has_Password_For
          (Manager_Information.Master_Database,Input_Url) and
            Manager_Information.Is_Locked = False) then
         Get_Database(Manager_Information, Input_Url);
      end if;
   end;

   -- Carries out Get Command
   procedure Get_Database(Manager_Information : in Information;
                         Input_Url : in PasswordDatabase.URL) is
   begin
      -- Returns associated password
         Put_Line (PasswordDatabase.To_String
                   (PasswordDatabase.Get
                      (Manager_Information.Master_Database,Input_Url)));
   end;

   -- Only executes Put Command if requirements are met
   procedure Execute_Put_Command(Manager_Information : in out Information;
                                 Input_Url : in PasswordDatabase.URL;
                                 Input_Pwd : in PasswordDatabase.Password) is
   begin
      -- If Password Manager is unlocked and entries are
      -- within maximum entry range then store entry to Database
      if (Manager_Information.Is_Locked = False
          and StoredDatabaseLength(Manager_Information)
          < PasswordDatabase.Max_Entries) then
         Put_Database(Manager_Information, Input_Url, Input_Pwd);
      end if;

   end;

   -- Carries out Put Command
   procedure Put_Database(Manager_Information : in out Information;
                          Input_Url : in PasswordDatabase.URL;
                          Input_Pwd : in PasswordDatabase.Password) is
   begin
         -- Put associated entry into database
      PasswordDatabase.Put(Manager_Information.Master_Database,
                           Input_Url, Input_Pwd);

   end;

   -- Only executes Rem Command if requirements are met
   procedure Execute_Rem_Command(Manager_Information : in out Information;
                                 Input_Url : in PasswordDatabase.URL) is
   begin
      -- If Password Manager is unlocked and Database contains entry
      -- for the Url then call Rem Command
      if (PasswordDatabase.Has_Password_For
          (Manager_Information.Master_Database, Input_Url) and
            Manager_Information.Is_Locked = False) then

         Rem_Database(Manager_Information, Input_Url);
      end if;

   end;


   -- Carries out Rem Command
   procedure Rem_Database(Manager_Information : in out Information;
                          Input_Url : in PasswordDatabase.URL) is
   begin
      -- Remove the associated entry
      PasswordDatabase.Remove(Manager_Information.Master_Database, Input_Url);
   end;

end PasswordManager;
