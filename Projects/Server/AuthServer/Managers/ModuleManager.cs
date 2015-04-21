/*
 * Copyright (C) 2012-2014 Arctium Emulation <http://arctium.org>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using AuthServer.Network.Sessions;
using Framework.Constants.Account;
using Framework.Constants.Misc;
using Framework.Database;
using Framework.Database.Auth.Entities;
using Framework.Logging;
using Framework.Misc;
using Framework.Network.Packets;

namespace AuthServer.Managers
{
    using Network.Packets;

    class ModuleManager : Singleton<ModuleManager>
    {
        public readonly List<Module> Modules;

        ModuleManager()
        {
            Modules = new List<Module>();

            UpdateModules();
        }

        public void UpdateModules()
        {
            Log.Message(LogType.Debug, "Loading auth modules...");

            var modules = DB.Auth.Select<Module>();

            foreach ( var m in modules.Where( m => AddModule(m, this.Modules) ) )
                Log.Message(LogType.Debug, "New auth module '{0}' loaded", m.Hash);

            Log.Message(LogType.Debug, "Successfully loaded {0} auth modules", Modules.Count);

            IsInitialized = true;
        }

        static bool AddModule(Module module, IList list)
        {
            if (!list.Contains(module))
                return list.Add(module) != -1;

            return false;
        }

        public static void WriteModuleHeader(Client client, AuthPacket packet, Module module, int size = 0)
        {
            packet.WriteFourCC(module.Type);
            packet.WriteFourCC("\0\0" + Enum.GetName(typeof(Regions), client.Session.Account.Region));
            packet.Write(module.Hash.ToByteArray());
            packet.Write(size == 0 ? module.Size : (uint)size, 10);
        }

        public static void WriteRiskFingerprint(Client client, AuthPacket packet)
        {
            var riskFingerprintModule = client.Modules.SingleOrDefault(m => m.Name == "RiskFingerprint");

            WriteModuleHeader(client, packet, riskFingerprintModule);
        }
    }
}
