using System;
using System.ComponentModel.DataAnnotations;

namespace YgAndroidQQSniffer.Extension
{
    public static class EnumEx
    {
        public static string GetDisplayName(this Enum t)
        {
            var t_type = t.GetType();
            var fieldName = Enum.GetName(t_type, t);
            var objs = t_type.GetField(fieldName).GetCustomAttributes(typeof(DisplayAttribute), false);
            return objs.Length > 0 ? ((DisplayAttribute)objs[0]).Name : null;
        }

        public static string GetDisplayDescription(this Enum t)
        {
            var t_type = t.GetType();
            var fieldName = Enum.GetName(t_type, t);
            var objs = t_type.GetField(fieldName).GetCustomAttributes(typeof(DisplayAttribute), false);
            return objs.Length > 0 ? ((DisplayAttribute)objs[0]).Description : null;
        }
    }
}
