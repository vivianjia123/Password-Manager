with PIN;
with PasswordDatabase;
with Ada.Containers; use Ada.Containers;
with Ada.Text_IO; use Ada.Text_IO;

package PasswordManager with SPARK_Mode is

   type Information is private;

   -- Private function returns length of database in Password Manager
   function StoredDatabaseLength(Manager_Information : in Information)
                                 return Ada.Containers.Count_Type;
   -- Private function returns Master Pin in Password Manager
   function GetMasterPin(Manager_Information: in Information) return PIN.PIN;

   -- Private function returns database in Password Manager
   function GetDatabase(Manager_Information: in Information) return PasswordDatabase.Database;

   -- Private function returns status of Password Manager
   function IsLocked(Manager_Information: in Information) return Boolean;

   -- Inital Password Manager Setup
   procedure Init(Pin_Input : in String;
                  Manager_Information : out Information) with
   Pre => (Pin_Input' Length = 4 and
                  (for all I in Pin_Input'Range => Pin_Input(I) >= '0'
                   and Pin_Input(I) <= '9'));

   -- Gets the current status of the Password Manager
   function Lock_Status(Manager_Information : in Information) return Boolean;

   -- Only executes Unlock_Manager if the current state is unlocked
   procedure Execute_Unlock(Manager_Information : in out Information;
                          Pin_Input : in PIN.PIN);

   -- Procedure changes state of the Password Manager to Unlocked
   procedure Unlock_Manager(Manager_Information : in out Information;
                            Pin_Input : in PIN.PIN) with
     Pre => (IsLocked(Manager_Information)),
     Post =>(if PIN."="(GetMasterPin(Manager_Information), Pin_Input)
               then IsLocked(Manager_Information) = False);

   -- Only executes Lock_Manager if the current state is unlocked
   procedure Execute_Lock(Manager_Information : in out Information;
                          Pin_Input : in PIN.PIN);

   -- Procedure changes state of the Password Manager to Locked
   procedure Lock_Manager(Manager_Information : in out Information;
                          Pin_Input : in PIN.PIN) with
     Pre => (IsLocked(Manager_Information) = False),
     Post => PIN."="(GetMasterPin(Manager_Information), Pin_Input) and
     IsLocked(Manager_Information);

   -- Only executes Get Command if requirements are met
   procedure Execute_Get_Command(Manager_Information : in Information;
                                 Input_Url : in PasswordDatabase.URL);

   -- Get Command executed
   procedure Get_Database(Manager_Information : in Information;
                          Input_Url : in PasswordDatabase.URL) with
     Pre => (IsLocked(Manager_Information) = False
             and PasswordDatabase.Has_Password_For
             (GetDatabase(Manager_Information), Input_Url));

   -- Only executes Put Command if requirements are met
   procedure Execute_Put_Command(Manager_Information : in out Information;
                          Input_Url : in PasswordDatabase.URL;
                          Input_Pwd : in PasswordDatabase.Password);

   -- Put Command executed
   procedure Put_Database(Manager_Information : in out Information;
                          Input_Url : in PasswordDatabase.URL;
                          Input_Pwd : in PasswordDatabase.Password) with
     Pre => (IsLocked(Manager_Information) = False and
                 StoredDatabaseLength(Manager_Information)
          < PasswordDatabase.Max_Entries);

   -- Only executes Rem Command if requirements are met
   procedure Execute_Rem_Command(Manager_Information : in out Information;
                                 Input_Url : in PasswordDatabase.URL);

   -- Rem Command executed
   procedure Rem_Database(Manager_Information : in out Information;
                          Input_Url : in PasswordDatabase.URL) with
     Pre => (IsLocked(Manager_Information) = False and
                 PasswordDatabase.Has_Password_For
             (GetDatabase(Manager_Information), Input_Url));

private
   -- Password Manager is Record which encapsulates
   -- Locked status, Master Pin and Master Database
   type Information is record
      Is_Locked : Boolean;
      Master_Pin : PIN.PIN;
      Master_Database : PasswordDatabase.Database;
   end record;

   -- private function declarations
   function GetMasterPin(Manager_Information: in Information) return PIN.PIN is
     (Manager_Information.Master_Pin);

   function StoredDatabaseLength(Manager_Information : in Information)
                                 return Ada.Containers.Count_Type is
     (PasswordDatabase.Length(Manager_Information.Master_Database));

   function GetDatabase(Manager_Information: in Information)
                        return PasswordDatabase.Database is
     (Manager_Information.Master_Database);

   function IsLocked(Manager_Information: in Information) return Boolean is
      (Manager_Information.Is_Locked);

end PasswordManager;
