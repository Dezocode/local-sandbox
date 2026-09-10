import { z } from 'zod';
import { receiptSchema } from '@/lib/contracts';
import { boundary,identity,input,putReceipt,HttpError } from '@/lib/server';
export async function POST(request:Request){return boundary(async()=>{const user=await identity();const {receipt}=await input(request,z.object({receipt:receiptSchema}).strict());if(receipt.origin==='cloud-sandbox')throw new HttpError(400,'Imported receipts must identify a native or shortcut origin.');await putReceipt(user.userId,receipt);return {ok:true};});}
