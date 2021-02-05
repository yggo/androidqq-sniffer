/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

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
