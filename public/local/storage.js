function requestValue(request){
  return new Promise((resolve,reject)=>{
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error??Error('IndexedDB request failed.'));
  });
}

function transactionDone(transaction){
  const result=new Promise((resolve,reject)=>{
    transaction.oncomplete=()=>resolve();
    transaction.onabort=()=>reject(transaction.error??Error('IndexedDB transaction was aborted.'));
    transaction.onerror=()=>reject(transaction.error??Error('IndexedDB transaction failed.'));
  });
  void result.catch(()=>undefined);
  return result;
}

function sameValue(left,right){return JSON.stringify(left)===JSON.stringify(right);}

export async function openLocalDatabase(factory=globalThis.indexedDB){
  if(!factory)throw Error('Encrypted browser storage is unavailable.');
  const request=factory.open('local-sandbox-private',2);
  request.onupgradeneeded=()=>{
    const database=request.result;
    if(!database.objectStoreNames.contains('vault'))database.createObjectStore('vault');
    if(!database.objectStoreNames.contains('drafts'))database.createObjectStore('drafts',{keyPath:'id'});
  };
  const database=await new Promise((resolve,reject)=>{
    let settled=false;
    request.onsuccess=()=>{if(settled){request.result.close();return;}settled=true;resolve(request.result);};
    request.onerror=()=>{if(!settled){settled=true;reject(request.error??Error('Encrypted browser storage could not open.'));}};
    request.onblocked=()=>{if(!settled){settled=true;reject(Error('Another Local Sandbox tab is blocking the storage upgrade. Close it, then reload this page.'));}};
  });
  database.onversionchange=()=>database.close();

  const vaultStore={
    async read(){
      const transaction=database.transaction('vault');
      const done=transactionDone(transaction);
      const value=await requestValue(transaction.objectStore('vault').get('personal'));
      await done;
      return value??null;
    },
    async compareAndSwap(expected,next){
      const transaction=database.transaction('vault','readwrite');
      const done=transactionDone(transaction);
      const store=transaction.objectStore('vault');
      const current=await requestValue(store.get('personal'));
      const matches=sameValue(current??null,expected??null);
      if(matches)store.put(next,'personal');
      await done;
      return matches;
    },
    async compareAndSwapAndClearDrafts(expected,next){
      const transaction=database.transaction(['vault','drafts'],'readwrite');
      const done=transactionDone(transaction);
      const store=transaction.objectStore('vault');
      const current=await requestValue(store.get('personal'));
      const matches=sameValue(current??null,expected??null);
      if(matches){store.put(next,'personal');transaction.objectStore('drafts').clear();}
      await done;
      return matches;
    },
  };

  const draftStore={
    async insertIfAbsent(record){
      const transaction=database.transaction('drafts','readwrite');
      const done=transactionDone(transaction);
      const store=transaction.objectStore('drafts');
      const current=await requestValue(store.get(record.id));
      const inserted=current===undefined;
      if(inserted)store.add(record);
      await done;
      return inserted;
    },
    async replaceIf(record,expectedETag){
      const transaction=database.transaction('drafts','readwrite');
      const done=transactionDone(transaction);
      const store=transaction.objectStore('drafts');
      const current=await requestValue(store.get(record.id));
      const replaced=current?.etag===expectedETag;
      if(replaced)store.put(record);
      await done;
      return replaced;
    },
    async deleteIf(id,expectedETag){
      const transaction=database.transaction('drafts','readwrite');
      const done=transactionDone(transaction);
      const store=transaction.objectStore('drafts');
      const current=await requestValue(store.get(id));
      const removed=current?.etag===expectedETag;
      if(removed)store.delete(id);
      await done;
      return removed;
    },
    async list(){
      const transaction=database.transaction('drafts');
      const done=transactionDone(transaction);
      const records=await requestValue(transaction.objectStore('drafts').getAll());
      await done;
      return records;
    },
  };

  return{vaultStore,draftStore,close:()=>database.close()};
}

export async function storagePersistenceReport(storageManager=globalThis.navigator?.storage){
  if(!storageManager?.persisted)return{kind:'unsupported',message:'This browser does not report whether local storage can be evicted.'};
  let persisted=await storageManager.persisted();
  if(!persisted&&storageManager.persist){await storageManager.persist();persisted=await storageManager.persisted();}
  const estimate=storageManager.estimate?await storageManager.estimate():null;
  const used=estimate?.usage;
  const quota=estimate?.quota;
  const amount=Number.isFinite(used)&&Number.isFinite(quota)?` ${(used/1048576).toFixed(1)} MB of ${(quota/1048576).toFixed(1)} MB is in use.`:'';
  return persisted
    ?{kind:'persisted',message:`The browser granted persistent storage.${amount}`}
    :{kind:'evictable',message:`The browser may remove this vault under storage pressure. Keep an encrypted backup.${amount}`};
}
