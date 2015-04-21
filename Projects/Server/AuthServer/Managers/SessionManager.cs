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

namespace AuthServer.Managers
{
    using System.Collections.Concurrent;
    using Framework.Database;
    using Framework.Misc;
    using Network.Sessions;

    class SessionManager : Singleton<SessionManager>
    {
        public ConcurrentDictionary<int, Client> Clients;

        SessionManager()
        {
            Clients = new ConcurrentDictionary<int, Client>();

            IsInitialized = true;
        }

        public void RemoveClient(int id)
        {
            var client = Clients[id];
            var session = client.Session;

            if (session.GameAccount != null)
            {
                session.GameAccount.IsOnline = false;

                DB.Auth.Update(session.GameAccount, "IsOnline");

                Manager.SessionMgr.Clients.TryRemove(id, out client);

                client.Dispose();
            }
        }
    }
}
