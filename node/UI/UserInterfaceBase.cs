namespace TangramXtgmNode.UI
{
    public abstract class UserInterfaceBase : IUserInterface
    {
        public abstract UserInterfaceChoice Do(UserInterfaceSection section);
        public abstract bool Do<T>(IUserInterfaceInput<T> input, out T output);

        protected string _topic;
        public IUserInterface SetTopic(string topic)
        {
            _topic = topic;
            return this;
        }
    }
}