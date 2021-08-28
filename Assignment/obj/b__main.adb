pragma Warnings (Off);
pragma Ada_95;
pragma Source_File_Name (ada_main, Spec_File_Name => "b__main.ads");
pragma Source_File_Name (ada_main, Body_File_Name => "b__main.adb");
pragma Suppress (Overflow_Check);
with Ada.Exceptions;

package body ada_main is

   E014 : Short_Integer; pragma Import (Ada, E014, "system__soft_links_E");
   E012 : Short_Integer; pragma Import (Ada, E012, "system__exception_table_E");
   E022 : Short_Integer; pragma Import (Ada, E022, "system__exceptions_E");
   E053 : Short_Integer; pragma Import (Ada, E053, "system__soft_links__initialize_E");
   E124 : Short_Integer; pragma Import (Ada, E124, "ada__containers_E");
   E068 : Short_Integer; pragma Import (Ada, E068, "ada__io_exceptions_E");
   E009 : Short_Integer; pragma Import (Ada, E009, "ada__strings_E");
   E090 : Short_Integer; pragma Import (Ada, E090, "system__os_lib_E");
   E070 : Short_Integer; pragma Import (Ada, E070, "ada__tags_E");
   E067 : Short_Integer; pragma Import (Ada, E067, "ada__streams_E");
   E093 : Short_Integer; pragma Import (Ada, E093, "system__file_control_block_E");
   E088 : Short_Integer; pragma Import (Ada, E088, "system__finalization_root_E");
   E086 : Short_Integer; pragma Import (Ada, E086, "ada__finalization_E");
   E085 : Short_Integer; pragma Import (Ada, E085, "system__file_io_E");
   E139 : Short_Integer; pragma Import (Ada, E139, "system__storage_pools_E");
   E133 : Short_Integer; pragma Import (Ada, E133, "system__finalization_masters_E");
   E131 : Short_Integer; pragma Import (Ada, E131, "system__storage_pools__subpools_E");
   E065 : Short_Integer; pragma Import (Ada, E065, "ada__text_io_E");
   E057 : Short_Integer; pragma Import (Ada, E057, "ada__strings__maps_E");
   E061 : Short_Integer; pragma Import (Ada, E061, "ada__strings__maps__constants_E");
   E115 : Short_Integer; pragma Import (Ada, E115, "mycommandline_E");
   E119 : Short_Integer; pragma Import (Ada, E119, "mystring_E");
   E121 : Short_Integer; pragma Import (Ada, E121, "mystringtokeniser_E");
   E123 : Short_Integer; pragma Import (Ada, E123, "passworddatabase_E");
   E147 : Short_Integer; pragma Import (Ada, E147, "pin_E");
   E145 : Short_Integer; pragma Import (Ada, E145, "passwordmanager_E");

   Sec_Default_Sized_Stacks : array (1 .. 1) of aliased System.Secondary_Stack.SS_Stack (System.Parameters.Runtime_Default_Sec_Stack_Size);

   Local_Priority_Specific_Dispatching : constant String := "";
   Local_Interrupt_States : constant String := "";

   Is_Elaborated : Boolean := False;

   procedure finalize_library is
   begin
      E123 := E123 - 1;
      declare
         procedure F1;
         pragma Import (Ada, F1, "passworddatabase__finalize_spec");
      begin
         F1;
      end;
      E065 := E065 - 1;
      declare
         procedure F2;
         pragma Import (Ada, F2, "ada__text_io__finalize_spec");
      begin
         F2;
      end;
      E131 := E131 - 1;
      declare
         procedure F3;
         pragma Import (Ada, F3, "system__storage_pools__subpools__finalize_spec");
      begin
         F3;
      end;
      E133 := E133 - 1;
      declare
         procedure F4;
         pragma Import (Ada, F4, "system__finalization_masters__finalize_spec");
      begin
         F4;
      end;
      declare
         procedure F5;
         pragma Import (Ada, F5, "system__file_io__finalize_body");
      begin
         E085 := E085 - 1;
         F5;
      end;
      declare
         procedure Reraise_Library_Exception_If_Any;
            pragma Import (Ada, Reraise_Library_Exception_If_Any, "__gnat_reraise_library_exception_if_any");
      begin
         Reraise_Library_Exception_If_Any;
      end;
   end finalize_library;

   procedure adafinal is
      procedure s_stalib_adafinal;
      pragma Import (C, s_stalib_adafinal, "system__standard_library__adafinal");

      procedure Runtime_Finalize;
      pragma Import (C, Runtime_Finalize, "__gnat_runtime_finalize");

   begin
      if not Is_Elaborated then
         return;
      end if;
      Is_Elaborated := False;
      Runtime_Finalize;
      s_stalib_adafinal;
   end adafinal;

   type No_Param_Proc is access procedure;

   procedure adainit is
      Main_Priority : Integer;
      pragma Import (C, Main_Priority, "__gl_main_priority");
      Time_Slice_Value : Integer;
      pragma Import (C, Time_Slice_Value, "__gl_time_slice_val");
      WC_Encoding : Character;
      pragma Import (C, WC_Encoding, "__gl_wc_encoding");
      Locking_Policy : Character;
      pragma Import (C, Locking_Policy, "__gl_locking_policy");
      Queuing_Policy : Character;
      pragma Import (C, Queuing_Policy, "__gl_queuing_policy");
      Task_Dispatching_Policy : Character;
      pragma Import (C, Task_Dispatching_Policy, "__gl_task_dispatching_policy");
      Priority_Specific_Dispatching : System.Address;
      pragma Import (C, Priority_Specific_Dispatching, "__gl_priority_specific_dispatching");
      Num_Specific_Dispatching : Integer;
      pragma Import (C, Num_Specific_Dispatching, "__gl_num_specific_dispatching");
      Main_CPU : Integer;
      pragma Import (C, Main_CPU, "__gl_main_cpu");
      Interrupt_States : System.Address;
      pragma Import (C, Interrupt_States, "__gl_interrupt_states");
      Num_Interrupt_States : Integer;
      pragma Import (C, Num_Interrupt_States, "__gl_num_interrupt_states");
      Unreserve_All_Interrupts : Integer;
      pragma Import (C, Unreserve_All_Interrupts, "__gl_unreserve_all_interrupts");
      Detect_Blocking : Integer;
      pragma Import (C, Detect_Blocking, "__gl_detect_blocking");
      Default_Stack_Size : Integer;
      pragma Import (C, Default_Stack_Size, "__gl_default_stack_size");
      Default_Secondary_Stack_Size : System.Parameters.Size_Type;
      pragma Import (C, Default_Secondary_Stack_Size, "__gnat_default_ss_size");
      Leap_Seconds_Support : Integer;
      pragma Import (C, Leap_Seconds_Support, "__gl_leap_seconds_support");
      Bind_Env_Addr : System.Address;
      pragma Import (C, Bind_Env_Addr, "__gl_bind_env_addr");

      procedure Runtime_Initialize (Install_Handler : Integer);
      pragma Import (C, Runtime_Initialize, "__gnat_runtime_initialize");

      Finalize_Library_Objects : No_Param_Proc;
      pragma Import (C, Finalize_Library_Objects, "__gnat_finalize_library_objects");
      Binder_Sec_Stacks_Count : Natural;
      pragma Import (Ada, Binder_Sec_Stacks_Count, "__gnat_binder_ss_count");
      Default_Sized_SS_Pool : System.Address;
      pragma Import (Ada, Default_Sized_SS_Pool, "__gnat_default_ss_pool");

   begin
      if Is_Elaborated then
         return;
      end if;
      Is_Elaborated := True;
      Main_Priority := -1;
      Time_Slice_Value := -1;
      WC_Encoding := 'b';
      Locking_Policy := ' ';
      Queuing_Policy := ' ';
      Task_Dispatching_Policy := ' ';
      Priority_Specific_Dispatching :=
        Local_Priority_Specific_Dispatching'Address;
      Num_Specific_Dispatching := 0;
      Main_CPU := -1;
      Interrupt_States := Local_Interrupt_States'Address;
      Num_Interrupt_States := 0;
      Unreserve_All_Interrupts := 0;
      Detect_Blocking := 0;
      Default_Stack_Size := -1;
      Leap_Seconds_Support := 0;

      ada_main'Elab_Body;
      Default_Secondary_Stack_Size := System.Parameters.Runtime_Default_Sec_Stack_Size;
      Binder_Sec_Stacks_Count := 1;
      Default_Sized_SS_Pool := Sec_Default_Sized_Stacks'Address;

      Runtime_Initialize (1);

      Finalize_Library_Objects := finalize_library'access;

      System.Soft_Links'Elab_Spec;
      System.Exception_Table'Elab_Body;
      E012 := E012 + 1;
      System.Exceptions'Elab_Spec;
      E022 := E022 + 1;
      System.Soft_Links.Initialize'Elab_Body;
      E053 := E053 + 1;
      E014 := E014 + 1;
      Ada.Containers'Elab_Spec;
      E124 := E124 + 1;
      Ada.Io_Exceptions'Elab_Spec;
      E068 := E068 + 1;
      Ada.Strings'Elab_Spec;
      E009 := E009 + 1;
      System.Os_Lib'Elab_Body;
      E090 := E090 + 1;
      Ada.Tags'Elab_Spec;
      Ada.Tags'Elab_Body;
      E070 := E070 + 1;
      Ada.Streams'Elab_Spec;
      E067 := E067 + 1;
      System.File_Control_Block'Elab_Spec;
      E093 := E093 + 1;
      System.Finalization_Root'Elab_Spec;
      E088 := E088 + 1;
      Ada.Finalization'Elab_Spec;
      E086 := E086 + 1;
      System.File_Io'Elab_Body;
      E085 := E085 + 1;
      System.Storage_Pools'Elab_Spec;
      E139 := E139 + 1;
      System.Finalization_Masters'Elab_Spec;
      System.Finalization_Masters'Elab_Body;
      E133 := E133 + 1;
      System.Storage_Pools.Subpools'Elab_Spec;
      E131 := E131 + 1;
      Ada.Text_Io'Elab_Spec;
      Ada.Text_Io'Elab_Body;
      E065 := E065 + 1;
      Ada.Strings.Maps'Elab_Spec;
      E057 := E057 + 1;
      Ada.Strings.Maps.Constants'Elab_Spec;
      E061 := E061 + 1;
      E115 := E115 + 1;
      E119 := E119 + 1;
      E121 := E121 + 1;
      Passworddatabase'Elab_Spec;
      E123 := E123 + 1;
      E147 := E147 + 1;
      E145 := E145 + 1;
   end adainit;

   procedure Ada_Main_Program;
   pragma Import (Ada, Ada_Main_Program, "_ada_main");

   function main
     (argc : Integer;
      argv : System.Address;
      envp : System.Address)
      return Integer
   is
      procedure Initialize (Addr : System.Address);
      pragma Import (C, Initialize, "__gnat_initialize");

      procedure Finalize;
      pragma Import (C, Finalize, "__gnat_finalize");
      SEH : aliased array (1 .. 2) of Integer;

      Ensure_Reference : aliased System.Address := Ada_Main_Program_Name'Address;
      pragma Volatile (Ensure_Reference);

   begin
      gnat_argc := argc;
      gnat_argv := argv;
      gnat_envp := envp;

      Initialize (SEH'Address);
      adainit;
      Ada_Main_Program;
      adafinal;
      Finalize;
      return (gnat_exit_status);
   end;

--  BEGIN Object file/option list
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/mycommandline.o
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/mystring.o
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/mystringtokeniser.o
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/passworddatabase.o
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/pin.o
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/passwordmanager.o
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/utility.o
   --   /Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/main.o
   --   -L/Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/
   --   -L/Users/catherinesong/Documents/SWEN90010/Assignment/Assignment 3/assignment3/obj/
   --   -L/users/catherinesong/opt/gnat/2019/lib/gcc/x86_64-apple-darwin17.7.0/8.3.1/adalib/
   --   -static
   --   -lgnat
--  END Object file/option list   

end ada_main;