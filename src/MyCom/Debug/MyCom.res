        ??  ??                  ?      ?? ??     0         ?4   V S _ V E R S I O N _ I N F O     ???               ?                       (   S t r i n g F i l e I n f o      0 8 0 4 0 4 B 0   :   C o m p a n y N a m e     T O D O :     < lQ?ST>     D   F i l e D e s c r i p t i o n     T O D O :     < ?e?N??f>   0   F i l e V e r s i o n     1 . 0 . 0 . 1   Z   L e g a l C o p y r i g h t   T O D O :     ( C )   < lQ?ST> 0    ?OYu@b	gCg)R0    4 
  I n t e r n a l N a m e   M y C o m . d l l   < 
  O r i g i n a l F i l e n a m e   M y C o m . d l l   :   P r o d u c t N a m e     T O D O :     < ?N?TT>     4   P r o d u c t V e r s i o n   1 . 0 . 0 . 1   D    V a r F i l e I n f o     $    T r a n s l a t i o n     ?  0   R E G I S T R Y   ??e       0         HKCR
{
	NoRemove CLSID
	{
		ForceRemove {fa998c86-13ca-42a7-9e46-a8c03973f7ce} = s 'CompReg Class'
		{
			InprocServer32 = s '%MODULE%'
			{
				val ThreadingModel = s 'Apartment'
			}
			TypeLib = s '{3cf0adcb-2625-470b-9325-e93da573a0ab}'
			Version = s '1.0'
		}
	}
}
  0  0   R E G I S T R Y   ??j       0         HKCR
{
	MyCom.math.1 = s 'MyClass class'
	{
		CLSID = s '{f606ffcd-1eee-43ca-b7bb-db3c196e15e1}'
	}
	MyCom.math = s 'MyClass class'
	{		
		CurVer = s 'MyCom.math.1'
	}
	NoRemove CLSID
	{
		ForceRemove {f606ffcd-1eee-43ca-b7bb-db3c196e15e1} = s 'MyClass class'
		{
			ProgID = s 'MyCom.math.1'
			VersionIndependentProgID = s 'MyCom.math'
			ForceRemove Programmable
			InprocServer32 = s '%MODULE%'
			{
				val ThreadingModel = s 'Apartment'
			}
			TypeLib = s '{3cf0adcb-2625-470b-9325-e93da573a0ab}'
			Version = s '1.0'
		}
	}
}
?
  ,   T Y P E L I B   ??     0         MSFT      	      A             ????           ?       ????$       ?             d   ?   ,  T  ?  ????   ?     ????   ?     ????   l      ????   ?  ?   ????   d    ????   ?     ????   ?  ?  ????   ????    ????   `     ????   ????    ????   x  ?   ????   ?  0   ????   ????    ????   ????    ????   %"  (	                                     x             ????        ????                  ????4" (	                                    ?   @  (       ????        ???? 4             ????%" @
                                     ?      P      ????        ????                 ????4" @
                                    ?   ?  d      ????        ????               ?????????????   ????????????????????????????x   ?????????   ?????   ?????????   ????????   ?   ????`   0   ????????????????????H   ˭?<%&G?%?=?s??????????????C??D ? ?w
????????e?w?|Q???  ?w<?????????c?w?|Q???  ?w<?????????d?w?|Q???  ?w<???????????????B?F??9s??        0     ?      F   ????      ?      F   ????????C??D ? ?w
d   ?????????C???<n??   ????Y???6@??;?y?`i,  ????d      ????????,     ????????      ?   ?          - stdole2.tlbWWW????????????????????????????????????????????????????????????????????????????\   ????????????????????????????????????????????????????P  ?   ?????????????????????????????????????????????????????????????????????????????????  ?????????????????   ?????????????   ????????????????????????????????    ????????(      ????????????????????????????????????????????????????????????????????????d  ????????p   ?????  ????????0  ????????????  x  ?????????????   ????????????????????????????H   ?   ???????????????????????????? IMyComLib    ????8MCompRegWd   ????8LXIComponentRegistrarWd   ???? ??AttachWW???????? ??bstrPathd   ???? c?RegisterAllWd   ???? "BUnregisterAllWWWd   ???? ??GetComponentsWWW???????? ?lpbstrCLSIDsW???????? <?pbstrDescriptionsWWWd   ???? ?[RegisterComponentWWW????????	 lbstrCLSIDWWWd   ???? hUnregisterComponentW?   ????8!?MyClassW,  ????8??IMyClass,  ???? m`TotalSum???????? enWWW???????? ??sumW   ? `     @ ? &   {fa998c86-13ca-42a7-9e46-a8c03973f7ce} >   Created by MIDL version 8.01.0622 at Tue Jan 19 11:14:07 2038
 ???WW nWW       ????0   ,       H   p      `   x      ?   $    ?     D 	      ?\         ?      4 	        ?    $ 4 	     0   ?    ( t 	       ?         ?      $   ?    , D 	     ?     $   ?    0 D 	     ?                       H   p   ?   ?   ?   0      $   <   T   ?   ?   0   0    ?     \ 	      ??        ?        x      *       ?? ??     0                 M y C o m                         