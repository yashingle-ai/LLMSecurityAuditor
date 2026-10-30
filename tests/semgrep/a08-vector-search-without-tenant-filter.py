def search_notes(user, arguments, store):
    # ruleid: llmaudit-a08-vector-search-without-tenant-filter
    return store.similarity_search(arguments["query"], k=3)


def ask_docs(collection, question):
    # ruleid: llmaudit-a08-vector-search-without-tenant-filter
    return collection.query(query_texts=[question], n_results=5)


def search_own_notes(user, arguments, store):
    # ok: llmaudit-a08-vector-search-without-tenant-filter
    return store.similarity_search(arguments["query"], k=3, filter={"customer": user})


def ask_tenant_docs(collection, question, tenant_id):
    # ok: llmaudit-a08-vector-search-without-tenant-filter
    return collection.query(query_texts=[question], where={"tenant": tenant_id})


def search_tenant_index(index, vector, tenant_id):
    # ok: llmaudit-a08-vector-search-without-tenant-filter
    return index.query(vector=vector, top_k=5, namespace=tenant_id)
