using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Web.Hosting;

namespace Cnaws.Web.Hosting
{
#if (MONO)
    public static class Mono
    {
        private class Watcher : IDisposable
        {
            private string _id;
            private string _path;
            private Action<string> _action;
            private FileSystemWatcher _watcher;
            private object _lock;

            public Watcher(string id, string root, Action<string> action)
            {
                _id = id;
                _path = root;
                _action = action;
                _watcher = null;
                _lock = new object();

                Init();
            }
            ~Watcher()
            {
                Dispose();
            }

            public void Dispose()
            {
                Uninit();
            }

            private void Init()
            {
                lock (_lock)
                {
                    if (_watcher == null)
                    {
                        _watcher = new FileSystemWatcher(_path);
                        _watcher.InternalBufferSize = 40960;
                        _watcher.IncludeSubdirectories = true;
                        _watcher.NotifyFilter = NotifyFilters.LastWrite;
                        _watcher.Deleted += OnChanged;
                        _watcher.Deleted += OnChanged;
                        _watcher.Deleted += OnChanged;
                        _watcher.Deleted += OnChanged;
                        _watcher.Error += OnError;
                        _watcher.EnableRaisingEvents = true;
                    }
                }
            }
            private void Uninit()
            {
                lock (_lock)
                {
                    if (_watcher != null)
                    {
                        _watcher.EnableRaisingEvents = false;
                        _watcher.Deleted -= OnChanged;
                        _watcher.Deleted -= OnChanged;
                        _watcher.Deleted -= OnChanged;
                        _watcher.Deleted -= OnChanged;
                        _watcher.Error -= OnError;
                        _watcher.Dispose();
                        _watcher = null;
                    }
                }
            }

            private void OnChanged(object sender, FileSystemEventArgs e)
            {
                if (e.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                    || "web.config".Equals(e.Name, StringComparison.OrdinalIgnoreCase))
                {
                    _action(_id);
                }
            }
            private void OnError(object sender, ErrorEventArgs e)
            {
                Uninit();
                Init();
            }
        }

        private static readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();
        private static readonly Dictionary<string, MonoApplicationHost> _hosts = new Dictionary<string, MonoApplicationHost>();
        private static readonly Dictionary<string, Watcher> _watchers = new Dictionary<string, Watcher>();

        private static MonoApplicationHost CreateHost(string root, string vroot)
        {
            MonoApplicationHost host = (MonoApplicationHost)ApplicationHost.CreateApplicationHost(typeof(MonoApplicationHost), vroot, root);
            host.Root = root;
            host.VRoot = vroot;
            return host;
        }
        private static void OnChanged(string id)
        {
            _lock.EnterWriteLock();
            try
            {
                MonoApplicationHost host;
                if (_hosts.TryGetValue(id, out host))
                {
                    RemoveWatcher(id);
                    RemoveHost(id);
                    AddHost(id, host.Root, host.VRoot);
                    AddWatcher(id, host.Root);
                }
                else
                {
                    RemoveWatcher(id);
                    RemoveHost(id);
                }
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }
        private static Watcher CreateWatcher(string id, string root)
        {
            Watcher watcher = new Watcher(id, root, OnChanged);
            return watcher;
        }

        private static void AddHost(string id, string root, string vroot)
        {
            _hosts.Add(id, CreateHost(root, vroot));
        }
        private static void RemoveHost(string id)
        {
            _hosts.Remove(id);
        }
        private static void AddWatcher(string id, string root)
        {
            _watchers.Add(id, CreateWatcher(id, root));
        }
        private static void RemoveWatcher(string id)
        {
            Watcher watcher;
            if (_watchers.TryGetValue(id, out watcher))
            {
                _watchers.Remove(id);
                watcher.Dispose();
            }
        }
        private static bool GetHost(string id, out MonoApplicationHost host)
        {
            _lock.EnterReadLock();
            try
            {
                return _hosts.TryGetValue(id, out host);
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public static string Register(string root, string vroot)
        {
#if DEBUG
            Console.Write($"Register: {root} {vroot}");
#endif
            _lock.EnterWriteLock();
            try
            {
                string id = Guid.NewGuid().ToString("N");
                AddHost(id, root, vroot);
                AddWatcher(id, root);
#if DEBUG
                Console.WriteLine($" OK {id}");
#endif
                return id;
            }
#if DEBUG
            catch (Exception ex)
            {
                Console.WriteLine($" fail {ex.ToString()}");
#else
            catch
            {
#endif
            }
            finally
            {
                _lock.ExitWriteLock();
            }
            return null;
        }
        public static void Unregister(string id)
        {
#if DEBUG
            Console.WriteLine($" Unregister: {id}");
#endif
            _lock.EnterWriteLock();
            try
            {
                RemoveWatcher(id);
                RemoveHost(id);
            }
            catch { }
            finally
            {
                _lock.ExitWriteLock();
            }
        }
        public static int ProcessRequest(string id, IntPtr request, IntPtr response)
        {
#if DEBUG
            Console.Write($"ProcessRequest: ");
#endif
            try
            {
                MonoApplicationHost host;
                if (GetHost(id, out host))
                {
                    if (!host.Unload)
                    {
#if DEBUG
                        Console.WriteLine($" {host.Root} {host.VRoot}");
#endif
                        return host.ProcessRequest(request, response);
                    }
                    else
                    {
                        OnChanged(id);
                        if (GetHost(id, out host) && !host.Unload)
                        {
                            return host.ProcessRequest(request, response);
                        }
#if DEBUG
                        Console.WriteLine($" unloadded");
#endif
                    }
                }
#if DEBUG
                Console.WriteLine($" fail");
#endif
            }
#if DEBUG
            catch (Exception ex)
            {
                Console.WriteLine($" fail {ex.ToString()}");
#else
            catch
            {
#endif
            }
            return 0;
        }
#endif

    }
}
