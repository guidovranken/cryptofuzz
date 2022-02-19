with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C; use Interfaces.C;
with Ada.Numerics.Big_Numbers.Big_Integers; use Ada.Numerics.Big_Numbers.Big_Integers;
procedure Cryptofuzz is
bn0 : Big_Integer;
bn1 : Big_Integer;
op : int;
res : Big_Integer;
begin
    op := 0;
    res := From_String("0");
    bn0 := From_String("123");
    bn1 := From_String("555");
    if op = 0 then
        res := bn0 + bn1;
    elsif op = 1 then
        res := bn0 - bn1;
    elsif op = 2 then
        res := bn0 * bn1;
    elsif op = 3 then
        res := bn0 / bn1;
    elsif op = 4 then
        res := Greatest_Common_Divisor(bn0, bn1);
    elsif op = 5 then
        res := Min(bn0, bn1);
    elsif op = 6 then
        res := Max(bn0, bn1);
    elsif op = 7 then
        res := bn0 mod bn1;
    elsif op = 8 then
        res := abs bn0;
    end if;
    Put_Line (To_String(res));
end Cryptofuzz;
