using System;
using System.Web;

namespace Cnaws.Web.Hosting
{
#if(MONO)
    public sealed class MonoApplicationHost : MarshalByRefObject
    {
#if (V1)
#else
        private string _root;
        private string _vroot;
#endif
        private bool _unload;

        public MonoApplicationHost()
        {
#if (V1)
#else
            _root = null;
            _vroot = null;
#endif
            _unload = false;
            
            AppDomain.CurrentDomain.DomainUnload += CurrentDomain_DomainUnload;
        }

#if (V1)
#else
        internal string Root
        {
            get { return _root; }
            set { _root = value; }
        }
        internal string VRoot
        {
            get { return _vroot; }
            set { _vroot = value; }
        }
#endif
        public bool Unload 
            => _unload;

        public override object InitializeLifetimeService() 
            => null;
        
        private void CurrentDomain_DomainUnload(object sender, EventArgs e)
            => _unload = true;

#if (V1)
        internal int ProcessRequest(string root, string vroot, IntPtr request, IntPtr response)
        {
            using (MonoWorkerRequest worker = new MonoWorkerRequest(root, vroot, request, response))
                worker.ProcessRequest();
            return 1;
        }
#else
        internal int ProcessRequest(IntPtr request, IntPtr response)
        {
            try
            {
                using (MonoWorkerRequest worker = new MonoWorkerRequest(_root, _vroot, request, response))
                {
                    try
                    {
                        worker.ProcessRequest();
                    }
                    catch (HttpException ex)
                    {
                        worker.Error(ex.GetHttpCode(), string.Concat("<h2>", ex.Message, "</h2>", ex.StackTrace.Replace("\r", string.Empty).Replace("\n", "<br/>")));
                    }
                    catch (Exception ex)
                    {
                        worker.Error(400, string.Concat("<h2>", ex.Message, "</h2>", ex.StackTrace.Replace("\r", string.Empty).Replace("\n", "<br/>")));
                    }
                }
                return 1;
            }
            catch { }
            return 0;
        }
#endif
    }
#endif
}
