using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Mortis.Server.Helpers
{
	public static class AsyncEnumerableExtensions
	{
		public static Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
		{
			if (source == null)
			{
				throw new ArgumentNullException("source");
			}
			return ExecuteAsync();
			async Task<List<T>> ExecuteAsync()
			{
				List<T> list = new List<T>();
				IAsyncEnumerator<T> asyncEnumerator = source.GetAsyncEnumerator();
				try
				{
					while (await asyncEnumerator.MoveNextAsync())
					{
						T element = asyncEnumerator.Current;
						list.Add(element);
					}
				}
				finally
				{
					if (asyncEnumerator != null)
					{
						await asyncEnumerator.DisposeAsync();
					}
				}
				return list;
			}
		}
	}
}
