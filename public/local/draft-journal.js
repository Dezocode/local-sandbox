import{newJournalRecordID,openJournalPayload,sealJournalPayload}from'./vault.js';

export class JournalWriteConflict extends Error{
  constructor(){super('A recovery draft changed in another tab. Review the conflict before saving.');this.name='JournalWriteConflict';}
}

export class EncryptedDraftJournal{
  constructor(store,session){this.store=store;this.session=session;}

  rekey(session){this.session=session;}

  async put(payload,token){
    if(token){
      const record=await sealJournalPayload(payload,this.session,token.id);
      if(!await this.store.replaceIf(record,token.etag))throw new JournalWriteConflict();
      return{id:record.id,etag:record.etag};
    }
    for(let attempt=0;attempt<3;attempt+=1){
      const record=await sealJournalPayload(payload,this.session,newJournalRecordID());
      if(await this.store.insertIfAbsent(record))return{id:record.id,etag:record.etag};
    }
    throw Error('Could not allocate an encrypted recovery record.');
  }

  async removeIf(token){return this.store.deleteIf(token.id,token.etag);}

  async list(){
    const storedRecords=await this.store.list();if(storedRecords.length>2000)throw Error('Too many encrypted recovery drafts.');
    const entries=[];
    for(const stored of storedRecords)entries.push({payload:await openJournalPayload(stored,this.session),token:{id:stored.id,etag:stored.etag}});
    return entries;
  }

  async removeAll(target){
    let removed=0;
    for(const entry of await this.list())if(entry.payload.target===target&&await this.removeIf(entry.token))removed+=1;
    return removed;
  }
}
